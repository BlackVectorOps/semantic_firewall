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

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// DiffPair names the two versions of one file. An empty path, a missing or
// empty file, or /dev/null stands for the absent side of an added or
// removed file, as in Diff.
type DiffPair struct {
	Old string
	New string
}

// loadFiles, fingerprintPackages and fingerprintSource load and fingerprint
// a group and a single file; tests replace them to count how files were
// loaded and to make a group fail.
var (
	loadFiles           = diff.LoadFiles
	fingerprintPackages = diff.FingerprintPackagesWhere
	fingerprintSource   = diff.FingerprintSourceWhere
)

// DiffBatch diffs every pair and returns one result per pair, in order.
// Each result is what Diff(pair.Old, pair.New) returns; a pair Diff would
// fail on has the error in its ErrorMessage and no functions.
//
// The files of each side are loaded together: all files under one module
// root, governed by the same go.work, take one go/packages call, so a
// package and its import graph are loaded once however many of its files
// are diffed. A file outside any module, a file the module's default build
// leaves out, a file of a package that does not type-check, and every file
// of a group whose load or SSA build fails are loaded on their own, exactly
// as Diff loads them.
func DiffBatch(pairs []DiffPair) []*models.DiffOutput {
	return DiffBatchWithFS(RealFileSystem{}, pairs)
}

// DiffBatchWithFS is DiffBatch against the supplied FileSystem. With any
// FileSystem but RealFileSystem, each file is loaded on its own, so each
// result is what DiffWithFS returns for its pair.
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
//
// A group shares a module root and the workspace that governs its files'
// directories, which Diff loads each file with: a .git entry between a
// file and its module root (a submodule) ends the workspace search for
// that file alone. Diff reads a file's package siblings from disk, so a
// FileSystem other than the disk, whose files a group load would overlay
// on each other, gets single-file loads only.
func fingerprintFiles(fsys FileSystem, paths []string) map[string]fileResult {
	out := make(map[string]fileResult)
	groups := make(map[string][]pendingFile)
	workspaces := make(map[string]string)
	_, onDisk := fsys.(RealFileSystem)
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
		root := ""
		if onDisk {
			root = moduleRoot(fsys, abs)
		}
		if root == "" {
			loose = append(loose, f)
			continue
		}
		dir := filepath.Dir(abs)
		work, seen := workspaces[dir]
		if !seen {
			work = diff.WorkspaceFile(dir)
			workspaces[dir] = work
		}
		key := root + "\x00" + work
		groups[key] = append(groups[key], f)
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for path, res := range fingerprintGroup(groups[k]) {
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
// with only whitespace (an empty file, or /dev/null standing in for the
// absent side of an added or removed file); any other stat or read error,
// or a file over models.MaxSourceFileSize, is an error. abs is the file's
// absolute path, which the loader reports its functions under: from the
// FileSystem, or from the working directory when the FileSystem gives no
// absolute path.
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
	if abs, err = fsys.Abs(path); err != nil || !filepath.IsAbs(abs) {
		if abs, err = filepath.Abs(path); err != nil {
			return nil, "", fmt.Errorf("failed to resolve %s: %w", path, err)
		}
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

// fingerprintGroup loads a group's files together, from the directory of
// the first, and fingerprints their packages, falling back to
// fingerprintOne for each file the group cannot cover.
func fingerprintGroup(files []pendingFile) map[string]fileResult {
	out := make(map[string]fileResult)
	overlay := make(map[string][]byte, len(files))
	for _, f := range files {
		overlay[f.abs] = f.content
	}
	pkgs, err := loadFiles(filepath.Dir(files[0].abs), overlay)
	// SSA skips an ill-typed package (one with errors, or with an ill-typed
	// dependency), and a single-file diff of its files fails. Build only the
	// well-typed packages here; the files of the others take the single-file
	// path, which reports the same error Diff does. An ad-hoc package is one
	// go list built of a single file its directory's package leaves out (a
	// GOOS suffix, a //go:build line), under the host's GOOS and GOARCH;
	// Diff loads such a file under a configuration that includes it, so its
	// files take the single-file path too.
	var wellTyped []*packages.Package
	for _, p := range pkgs {
		if !p.IllTyped && p.PkgPath != "command-line-arguments" {
			wellTyped = append(wellTyped, p)
		}
	}
	paths := pathResolver{}
	abs := make([]string, len(files))
	for i, f := range files {
		abs[i] = f.abs
	}
	var results []diff.FingerprintResult
	if err == nil && len(wellTyped) > 0 {
		results, err = fingerprintPackagesSafely(wellTyped, paths.keepFiles(abs...))
	}
	for _, f := range files {
		if err != nil || !diff.PackagesContain(wellTyped, f.abs) {
			out[f.path] = fingerprintOne(f)
			continue
		}
		out[f.path] = fileResult{results: inFileOf(results, f.abs, packagesOf(wellTyped, f.abs), paths)}
	}
	return out
}

// fingerprintPackagesSafely fingerprints the functions of pkgs in the
// files keep accepts, turning a panic into an error.
func fingerprintPackagesSafely(pkgs []*packages.Package, keep func(string) bool) (results []diff.FingerprintResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic while fingerprinting: %v", r)
		}
	}()
	return fingerprintPackages(pkgs, ir.DefaultLiteralPolicy, false, keep)
}

// fingerprintOne loads and fingerprints one file on its own, as Diff does.
func fingerprintOne(f pendingFile) (res fileResult) {
	defer func() {
		if r := recover(); r != nil {
			res = fileResult{err: fmt.Errorf("panic while fingerprinting %s: %v", f.path, r)}
		}
	}()
	paths := pathResolver{}
	results, err := fingerprintSource(f.abs, string(f.content), ir.DefaultLiteralPolicy, false, paths.keepFiles(f.abs))
	if err != nil {
		return fileResult{err: err}
	}
	return fileResult{results: inFile(results, f.abs, paths)}
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
// functions of the file's own packages declared in the file at path, and
// those without a source file (the synthesized package initializer), as
// Diff, which loads only those packages, does. A function of another
// package can claim the file with a //line directive.
func inFileOf(results []diff.FingerprintResult, path string, own map[*types.Package]bool, paths pathResolver) []diff.FingerprintResult {
	kept := inFile(results, path, paths)
	out := kept[:0:0]
	for _, r := range kept {
		// Every function fingerprinted is a package member, a method or a
		// closure of one, which has its package.
		if fn := r.GetSSAFunction(); fn.Pkg != nil && own[fn.Pkg.Pkg] {
			out = append(out, r)
		}
	}
	return out
}
