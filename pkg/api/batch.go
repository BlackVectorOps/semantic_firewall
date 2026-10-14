package api

import (
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

// DiffPair names the two versions of one file. An empty path, a missing or
// empty file, or /dev/null stands for the absent side of an added or
// removed file, as in Diff.
type DiffPair struct {
	Old string
	New string
}

// loadFiles and fingerprintSource are the group and single-file loaders;
// tests replace them to count how files were loaded.
var (
	loadFiles         = diff.LoadFiles
	fingerprintSource = diff.FingerprintSource
)

// DiffBatch diffs every pair and returns one result per pair, in order.
// Each result is what Diff(pair.Old, pair.New) returns; a pair Diff would
// fail on has the error in its ErrorMessage and no functions.
//
// The files of each side are loaded together: all files under one module
// root take one go/packages call, so a package and its import graph are
// loaded once however many of its files are diffed. A file outside any
// module, a file the module's default build leaves out, a file of a package
// that does not type-check, and every file of a group whose load or SSA
// build fails are loaded on their own, exactly as Diff loads them.
func DiffBatch(pairs []DiffPair) []*models.DiffOutput {
	return DiffBatchWithFS(RealFileSystem{}, pairs)
}

// DiffBatchWithFS is DiffBatch against the supplied FileSystem.
func DiffBatchWithFS(fsys FileSystem, pairs []DiffPair) []*models.DiffOutput {
	oldPaths := make([]string, len(pairs))
	newPaths := make([]string, len(pairs))
	for i, p := range pairs {
		oldPaths[i], newPaths[i] = p.Old, p.New
	}
	// The two trees are independent; load them at the same time. They
	// share the loader's cache of standard-library and pinned-module types.
	var oldSide, newSide map[string]fileResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); oldSide = fingerprintFiles(fsys, oldPaths) }()
	go func() { defer wg.Done(); newSide = fingerprintFiles(fsys, newPaths) }()
	wg.Wait()

	out := make([]*models.DiffOutput, len(pairs))
	for i, p := range pairs {
		o, n := oldSide[p.Old], newSide[p.New]
		switch {
		case o.err != nil:
			out[i] = failedDiff(p, fmt.Errorf("failed to process old file: %w", o.err))
		case n.err != nil:
			out[i] = failedDiff(p, fmt.Errorf("failed to process new file: %w", n.err))
		default:
			out[i] = diffResults(p.Old, p.New, o.results, n.results, riskProfile{})
		}
	}
	return out
}

func failedDiff(p DiffPair, err error) *models.DiffOutput {
	return &models.DiffOutput{OldFile: p.Old, NewFile: p.New, Functions: []models.FunctionDiff{}, ErrorMessage: err.Error()}
}

// fileResult is one file's fingerprinted functions, or why there are none.
type fileResult struct {
	results []diff.FingerprintResult
	err     error
}

// pendingFile is a file to load: its absolute path and content.
type pendingFile struct {
	path, abs string
	content   []byte
}

// fingerprintFiles fingerprints each distinct path of one side, keyed by
// the path as given.
func fingerprintFiles(fsys FileSystem, paths []string) map[string]fileResult {
	out := make(map[string]fileResult)
	groups := make(map[string][]pendingFile)
	var loose []pendingFile
	for _, path := range paths {
		if _, done := out[path]; done {
			continue
		}
		content, abs, err := readDiffInput(fsys, path)
		if err != nil || content == nil {
			out[path] = fileResult{results: []diff.FingerprintResult{}, err: err}
			continue
		}
		out[path] = fileResult{} // claimed; filled in below
		f := pendingFile{path: path, abs: abs, content: content}
		if root := moduleRoot(fsys, abs); root != "" {
			groups[root] = append(groups[root], f)
		} else {
			loose = append(loose, f)
		}
	}

	roots := make([]string, 0, len(groups))
	for r := range groups {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	for _, root := range roots {
		for path, res := range fingerprintGroup(root, groups[root]) {
			out[path] = res
		}
	}
	for _, f := range loose {
		out[f.path] = fingerprintOne(f)
	}
	return out
}

// readDiffInput applies Diff's input rules to one path: an empty path or a
// missing file has no functions (nil content, nil error), as has a file
// with only whitespace; any other stat or read error, or a file over
// models.MaxSourceFileSize, is an error.
func readDiffInput(fsys FileSystem, path string) (content []byte, abs string, err error) {
	if path == "" {
		return nil, "", nil
	}
	info, err := fsys.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("failed to stat %s: %w", path, err)
	}
	if info.Size() > models.MaxSourceFileSize {
		return nil, "", fmt.Errorf("file %s exceeds maximum analysis size of %d bytes", path, models.MaxSourceFileSize)
	}
	content, err = fsys.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		return nil, "", nil
	}
	abs, err = fsys.Abs(path)
	if err != nil {
		abs = path
	}
	return content, abs, nil
}

// moduleRoot returns the directory of the go.mod nearest above abs, or ""
// when there is none.
func moduleRoot(fsys FileSystem, abs string) string {
	dir := filepath.Dir(abs)
	for {
		if info, err := fsys.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// fingerprintGroup loads the files under one module root together and
// fingerprints their packages, falling back to fingerprintOne for each file
// the group cannot cover.
func fingerprintGroup(root string, files []pendingFile) map[string]fileResult {
	out := make(map[string]fileResult)
	overlay := make(map[string][]byte, len(files))
	for _, f := range files {
		overlay[f.abs] = f.content
	}
	pkgs, err := loadFiles(root, overlay)
	// SSA skips an ill-typed package (one with errors, or with an ill-typed
	// dependency), and a single-file diff of its files fails. Build only the
	// well-typed packages here; the files of the others take the single-file
	// path, which reports the same error Diff does.
	var wellTyped []*packages.Package
	for _, p := range pkgs {
		if !p.IllTyped {
			wellTyped = append(wellTyped, p)
		}
	}
	var results []diff.FingerprintResult
	if err == nil && len(wellTyped) > 0 {
		results, err = fingerprintPackagesSafely(wellTyped)
	}
	for _, f := range files {
		if err != nil || !diff.PackagesContain(wellTyped, f.abs) || diff.PackagesContain(illTyped(pkgs), f.abs) {
			out[f.path] = fingerprintOne(f)
			continue
		}
		out[f.path] = fileResult{results: inFileOf(results, f.abs, packagesOf(wellTyped, f.abs))}
	}
	return out
}

func illTyped(pkgs []*packages.Package) []*packages.Package {
	var out []*packages.Package
	for _, p := range pkgs {
		if p.IllTyped {
			out = append(out, p)
		}
	}
	return out
}

func fingerprintPackagesSafely(pkgs []*packages.Package) (results []diff.FingerprintResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic while fingerprinting: %v", r)
		}
	}()
	return diff.FingerprintPackages(pkgs, ir.DefaultLiteralPolicy, false)
}

// fingerprintOne loads and fingerprints one file on its own, as Diff does.
func fingerprintOne(f pendingFile) (res fileResult) {
	defer func() {
		if r := recover(); r != nil {
			res = fileResult{err: fmt.Errorf("panic while fingerprinting %s: %v", f.path, r)}
		}
	}()
	results, err := fingerprintSource(f.abs, string(f.content), ir.DefaultLiteralPolicy)
	if err != nil {
		return fileResult{err: err}
	}
	return fileResult{results: inFile(results, f.abs)}
}

// packagesOf returns the type-checked packages among pkgs that compile the
// file at abs.
func packagesOf(pkgs []*packages.Package, abs string) map[*types.Package]bool {
	out := make(map[*types.Package]bool)
	for _, p := range pkgs {
		if p.Types != nil && diff.PackagesContain([]*packages.Package{p}, abs) {
			out[p.Types] = true
		}
	}
	return out
}

// inFileOf is inFile for results drawn from several packages: it keeps the
// functions declared in the file at path, and the functions without a
// source file (the synthesized package initializer) of the file's own
// packages only.
func inFileOf(results []diff.FingerprintResult, path string, own map[*types.Package]bool) []diff.FingerprintResult {
	kept := inFile(results, path)
	out := kept[:0:0]
	for _, r := range kept {
		if r.Filename == "" {
			fn := r.GetSSAFunction()
			if fn == nil || fn.Pkg == nil || !own[fn.Pkg.Pkg] {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
