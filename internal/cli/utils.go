// -- internal/cli/utils.go --
package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/diff"
	"golang.org/x/tools/go/packages"
)

// -- Real Implementations --

// RealFileSystem is re-exported from pkg/api so internal callers stay
// on the existing name while external integrations import the
// canonical version from pkg/api directly.
type RealFileSystem = api.RealFileSystem

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

// ShortFunctionName delegates to pkg/api so the CLI and external
// integrations share a single implementation. Kept as a wrapper rather
// than a re-export to avoid forcing every internal/cli caller to
// import pkg/api directly.
func ShortFunctionName(fullName string) string {
	return api.ShortFunctionName(fullName)
}

func IsJSON(path string) bool {
	return strings.HasSuffix(path, ".json")
}

func ExitError(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
