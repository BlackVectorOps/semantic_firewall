// -- internal/cli/utils.go --
package cli

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/models"
	"golang.org/x/tools/go/packages"
)

// -- Real Implementations --

// RealFileSystem implements FileSystem using the actual OS.
type RealFileSystem struct{}

func (fs RealFileSystem) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }
func (fs RealFileSystem) Open(name string) (fs.File, error)     { return os.Open(name) }
func (fs RealFileSystem) Getwd() (string, error)                { return os.Getwd() }
func (fs RealFileSystem) Abs(path string) (string, error)       { return filepath.Abs(path) }
func (fs RealFileSystem) WalkDir(root string, fn fs.WalkDirFunc) error {
	return filepath.WalkDir(root, fn)
}
func (fs RealFileSystem) ReadFile(name string) ([]byte, error) {
	// Re-implement safety logic here to ensure it applies to all users
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory: %s", name)
	}
	if info.Size() > models.MaxSourceFileSize {
		return nil, fmt.Errorf("file exceeds maximum supported size of %d bytes", models.MaxSourceFileSize)
	}

	limit := int64(models.MaxSourceFileSize + 1)
	content, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	if len(content) > models.MaxSourceFileSize {
		return nil, fmt.Errorf("file exceeds maximum supported size of %d bytes", models.MaxSourceFileSize)
	}
	return content, nil
}

// RealPackageLoader wraps packages.Load
type RealPackageLoader struct{}

func (p RealPackageLoader) Load(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
	return packages.Load(cfg, patterns...)
}

// -- Helpers --

func ResolveDBPath(path string) string {
	if path != "" {
		return path
	}
	if env := os.Getenv("SFW_DB_PATH"); env != "" {
		return env
	}
	candidates := []string{
		"./signatures.db",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".sfw", "signatures.db"))
	}
	candidates = append(candidates,
		"/usr/local/share/sfw/signatures.db",
		"/var/lib/sfw/signatures.db",
	)
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "./signatures.db"
}

func levenshtein(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	n, m := len(r1), len(r2)
	if n > m {
		r1, r2 = r2, r1
		n, m = m, n
	}
	current := make([]int, n+1)
	for i := 0; i <= n; i++ {
		current[i] = i
	}
	for j := 1; j <= m; j++ {
		previous := current[0]
		current[0] = j
		targetChar := r2[j-1]
		for i := 1; i <= n; i++ {
			temp := current[i]
			cost := 0
			if r1[i-1] != targetChar {
				cost = 1
			}
			// Use built-in variadic min for cleaner comparison logic
			current[i] = min(current[i-1]+1, current[i]+1, previous+cost)
			previous = temp
		}
	}
	return current[n]
}

func SuggestCommand(cmd string) string {
	commands := []string{"check", "diff", "audit", "index", "scan", "migrate", "stats"}
	bestMatch := ""
	minDist := 100
	cmdLower := strings.ToLower(cmd)
	for _, c := range commands {
		dist := levenshtein(cmdLower, c)
		if dist < minDist {
			minDist = dist
			bestMatch = c
		}
	}
	if minDist <= 2 {
		return bestMatch
	}
	return ""
}

func HumanizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	suffixes := "KMGTPE"
	if exp >= len(suffixes) {
		exp = len(suffixes) - 1
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), suffixes[exp])
}

// Recursively finds Go files using the provided FileSystem.
func CollectFiles(fsys FileSystem, target string) ([]string, error) {
	// Clean the target path to ensure reliable string comparison
	target = filepath.Clean(target)
	info, err := fsys.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if strings.HasSuffix(target, ".go") && !isTestFile(target) {
			return []string{target}, nil
		}
		return nil, nil
	}
	var files []string

	err = fsys.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			// Skip vendor and hidden directories to avoid scanning dependencies or metadata.
			if name == "vendor" || (len(name) > 1 && strings.HasPrefix(name, ".")) {
				if path != target {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !isTestFile(path) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func isTestFile(path string) bool {
	base := filepath.Base(path)
	return len(base) >= 8 && base[len(base)-8:] == "_test.go"
}

// Calculates the size of a file or recursively sums the size of a directory.
func GetPathSize(fsys FileSystem, path string) (int64, error) {
	info, err := fsys.Stat(path)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return info.Size(), nil
	}

	var size int64
	err = fsys.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err == nil {
				size += info.Size()
			}
		}
		return nil
	})
	return size, err
}

// This reads a file and generates semantic fingerprints using the provided FS.
func LoadAndFingerprint(fsys FileSystem, filename string) ([]diff.FingerprintResult, error) {
	absPath, err := fsys.Abs(filename)
	if err != nil {
		return nil, err
	}

	src, err := fsys.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	return diff.FingerprintSource(absPath, string(src), ir.DefaultLiteralPolicy)
}

func ShortFunctionName(fullName string) string {
	// Robust parsing for methods with receivers (e.g. (*pkg.Type).Method)
	// Will detect the receiver parens and recursively strip the package from the type inside.
	if strings.HasPrefix(fullName, "(") {
		depth := 0
		closeIndex := -1
		for i, c := range fullName {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					closeIndex = i
					break
				}
			}
		}

		if closeIndex > 1 {
			receiver := fullName[1:closeIndex] // e.g. "*pkg.Type"
			rest := fullName[closeIndex+1:]    // e.g. ".Method"

			// Preserve pointer indicator
			prefix := ""
			if strings.HasPrefix(receiver, "*") {
				prefix = "*"
				receiver = receiver[1:]
			}

			// Recursively clean the inner type (strips path and package)
			cleanReceiver := ShortFunctionName(receiver)

			return fmt.Sprintf("(%s%s)%s", prefix, cleanReceiver, rest)
		}
	}

	// 1. Backward Scan: Strip package path
	// e.g. "github.com/pkg.Func" -> "pkg.Func"
	// Must respect brackets [] and parens () to avoid splitting inside generics
	end := len(fullName) - 1
	depthBrackets := 0
	depthParens := 0
	splitIndex := -1

	for i := end; i >= 0; i-- {
		b := fullName[i]
		switch b {
		case ']':
			depthBrackets++
		case '[':
			depthBrackets--
		case ')':
			depthParens++
		case '(':
			depthParens--
		case '/':
			if depthBrackets == 0 && depthParens == 0 {
				splitIndex = i
				goto FoundSplit
			}
		}
	}
FoundSplit:
	name := fullName
	if splitIndex >= 0 {
		name = fullName[splitIndex+1:]
	}

	// 2. Forward Scan: Strip package name from qualified identifier
	// We scan for the first dot at depth 0.
	// Heuristic: If the prefix before the dot contains brackets or parens,
	// it's likely a receiver type (e.g. Type[T]) and NOT a package name.
	depth := 0
	for i, ch := range name {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case '[':
			depth++
		case ']':
			depth--
		case '.':
			if depth == 0 {
				prefix := name[:i]
				// If prefix has special characters, assume it is part of the type signature
				// (e.g. Type[T].Method) and preserve it.
				// If prefix is clean (e.g. pkg.Func), strip it.
				if !containsSpecial(prefix) {
					return name[i+1:]
				}
				return name
			}
		}
	}
	return name
}

func containsSpecial(s string) bool {
	return strings.ContainsAny(s, "[]()")
}

func IsJSON(path string) bool {
	return strings.HasSuffix(path, ".json")
}

func ExitError(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
