// -- internal/cli/utils.go --
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/diff"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
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
	commands := []string{"check", "diff", "deps", "audit", "index", "scan", "migrate", "stats"}
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

// fingerprintFiles fingerprints the functions declared in files (see
// api.FingerprintFiles) and returns each function once: the package
// initializer every file of a package lists is kept for the first. A file
// that fails to load is skipped with a warning.
func fingerprintFiles(fsys FileSystem, files []string) []diff.FingerprintResult {
	fingerprints := api.FingerprintFiles(fsys, files, false)
	seen := make(map[funcKey]bool)
	keys := funcKeys{}
	var out []diff.FingerprintResult
	for _, f := range files {
		fp, ok := fingerprints[f]
		if !ok {
			fp.Err = fmt.Errorf("no fingerprint result")
		}
		if fp.Err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", f, fp.Err)
			continue
		}
		dir := fileDir(f)
		for _, r := range fp.Results {
			if k := keys.of(dir, r); r.GetSSAFunction() != nil && !seen[k] {
				seen[k] = true
				out = append(out, r)
			}
		}
	}
	return out
}

// funcKey identifies a fingerprinted function across loads. Files the
// grouped load cannot cover (outside a module, excluded by the default
// build, in an ill-typed package) are loaded on their own, each into its
// own SSA program, so one package initializer can come back as several
// *ssa.Function values.
type funcKey struct {
	dir, pkg, name, file string
	line                 int
	fingerprint          string
}

// funcKeys computes funcKeys, hashing each initializer's content once: in a
// grouped load every file of a package lists the same initializer.
type funcKeys map[*ssa.Function]string

// of is the funcKey of r, listed under a file in dir (see fileDir). A
// function with a source file is identified by its name, position and
// fingerprint. One without (the package initializer) is identified by its
// name, its package, dir and what scanning reads of it (see contentHash):
// two separate loads of a directory can give initializers that differ only
// in a string or a type the fingerprint does not capture (a payload in a
// _windows.go file beside a benign _linux.go one), and both must be scanned.
func (c funcKeys) of(dir string, r diff.FingerprintResult) funcKey {
	k := funcKey{name: r.FunctionName, file: r.Filename, line: r.Line, fingerprint: r.Fingerprint}
	fn := r.GetSSAFunction()
	if r.Filename != "" || fn == nil {
		return k
	}
	k.dir = dir
	if fn.Pkg != nil {
		k.pkg = fn.Pkg.Pkg.Path()
	}
	h, ok := c[fn]
	if !ok {
		h = contentHash(fn)
		c[fn] = h
	}
	k.fingerprint = h
	return k
}

// contentHash hashes what scanning and indexing read of fn: its topology,
// every exported field of it (detection sees no other). Two initializers
// with equal hashes therefore give the same alerts and the same signature;
// a fingerprint would not do, since it masks literals and, for a function
// over diff.MaxFunctionBlocks, is taken from go/ssa's printing, which
// truncates constants and omits operand types. A topology that cannot be
// extracted (a panic, which the scan of fn then meets and reports) or
// encoded (a NaN score) gets a hash of its own, so it merges with nothing.
func contentHash(fn *ssa.Function) (hash string) {
	unique := fmt.Sprintf("unhashable:%p", fn)
	defer func() {
		if recover() != nil {
			hash = unique
		}
	}()
	data, err := json.Marshal(extractTopology(fn))
	if err != nil {
		return unique
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// extractTopology is topology.ExtractTopology; tests make it panic.
var extractTopology = topology.ExtractTopology

// fileDir is the absolute directory of the file at path, so different
// spellings of one directory give one funcKey.
func fileDir(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return filepath.Dir(path)
}

// resultName is the reported name of a fingerprinted function; see
// api.ResultName.
func resultName(r diff.FingerprintResult) string {
	return api.ResultName(r)
}

// ssaFunctionName is fn's package-relative name; see api.SSAFunctionName.
func ssaFunctionName(fn *ssa.Function) string {
	return api.SSAFunctionName(fn)
}

func IsJSON(path string) bool {
	return strings.HasSuffix(path, ".json")
}

func ExitError(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
