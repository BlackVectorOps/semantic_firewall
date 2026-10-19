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

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
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
	var oldSide, newSide map[string]FileFingerprints
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); oldSide = fingerprintFiles(fsys, oldPaths, readDiffInput, false) }()
	go func() { defer wg.Done(); newSide = fingerprintFiles(fsys, newPaths, readDiffInput, false) }()
	wg.Wait()

	out := make([]*models.DiffOutput, len(pairs))
	for i, p := range pairs {
		o, n := oldSide[p.Old], newSide[p.New]
		switch {
		case o.Err != nil:
			out[i] = failedDiff(p, fmt.Errorf("failed to process old file: %w", o.Err))
		case n.Err != nil:
			out[i] = failedDiff(p, fmt.Errorf("failed to process new file: %w", n.Err))
		default:
			out[i] = diffResults(p.Old, p.New, o, n, riskProfile{})
		}
	}
	return out
}

// FingerprintFiles fingerprints the functions declared in each file at
// paths. The result has one entry per distinct path, keyed by the path as
// given. Each entry is what a load of that file alone gives: its functions
// and its package's initializer, not its package siblings', or the error
// that load fails with. Unlike DiffBatch's inputs, every path must name a
// file: an empty path, a missing file, a file with only whitespace, a file
// over models.MaxSourceFileSize and a path that cannot be resolved are
// errors. Results is nil or empty when Err is set.
//
// With RealFileSystem, files are loaded as DiffBatch loads them: all files
// under one module root and governed by the same go.work with one
// go/packages call, so a package is loaded and canonicalized once however
// many of its files are listed, and the results of one package share their
// SSA functions. Any other FileSystem, every file the grouped load cannot
// cover (outside a module, excluded by the default build, in an ill-typed
// package), and every file of a group whose load or fingerprinting fails,
// is loaded on its own.
//
// With strict, an SSA instruction the canonicalizer does not handle fails
// the file ("panic while fingerprinting <path>: STRICT MODE: ...") instead
// of rendering as a placeholder. A panic in the FileSystem fails its file
// too.
func FingerprintFiles(fsys FileSystem, paths []string, strict bool) map[string]FileFingerprints {
	return fingerprintFiles(fsys, paths, readSourceInput, strict)
}

func failedDiff(p DiffPair, err error) *models.DiffOutput {
	return &models.DiffOutput{OldFile: p.Old, NewFile: p.New, Functions: []models.FunctionDiff{}, ErrorMessage: err.Error()}
}

// FileFingerprints is one file's fingerprinted functions, or why there are
// none.
type FileFingerprints struct {
	Results []diff.FingerprintResult
	Err     error

	// source holds what the file's text declares that its SSA does not show
	// (see parseUnanalyzed).
	source unanalyzedSource
}

// inputReader reads a file to fingerprint: its content, or nil when the
// path stands for a file with no functions, and its absolute path.
type inputReader func(fsys FileSystem, path string) (content []byte, abs string, err error)

// pendingFile is a file to load: its absolute path and content.
type pendingFile struct {
	path, abs string
	content   []byte
}

// fingerprintFiles fingerprints each distinct path, read with read, keyed
// by the path as given.
//
// A group shares a module root and the workspace that governs its files'
// directories, which Diff loads each file with: a .git entry between a
// file and its module root (a submodule) ends the workspace search for
// that file alone. Diff reads a file's package siblings from disk, so a
// FileSystem other than the disk, whose files a group load would overlay
// on each other, gets single-file loads only.
func fingerprintFiles(fsys FileSystem, paths []string, read inputReader, strict bool) map[string]FileFingerprints {
	out := make(map[string]FileFingerprints)
	groups := make(map[string][]pendingFile)
	workspaces := make(map[string]string)
	_, onDisk := fsys.(RealFileSystem)
	var loose, sources []pendingFile
	for _, path := range paths {
		if _, done := out[path]; done {
			continue
		}
		content, abs, err := readSafely(read, fsys, path)
		if err != nil || content == nil {
			out[path] = FileFingerprints{Results: []diff.FingerprintResult{}, Err: err}
			continue
		}
		out[path] = FileFingerprints{} // claimed; filled in below
		f := pendingFile{path: path, abs: abs, content: content}
		sources = append(sources, f)
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
		for path, res := range fingerprintGroup(groups[k], strict) {
			out[path] = res
		}
	}
	for _, f := range loose {
		out[f.path] = fingerprintOne(f, strict)
	}
	// Body-less functions and linkname directives come from the source text,
	// which the loads above do not keep.
	for _, f := range sources {
		r := out[f.path]
		r.source = parseUnanalyzed(f.content)
		out[f.path] = r
	}
	return out
}

// readSafely is read, turning a panic in the FileSystem into the file's
// error.
func readSafely(read inputReader, fsys FileSystem, path string) (content []byte, abs string, err error) {
	defer func() {
		if r := recover(); r != nil {
			content, abs, err = nil, "", fmt.Errorf("panic while reading %s: %v", path, r)
		}
	}()
	return read(fsys, path)
}

// readSourceInput reads a file to fingerprint: a stat or read error, a file
// over models.MaxSourceFileSize and a file with only whitespace are errors.
func readSourceInput(fsys FileSystem, path string) (content []byte, abs string, err error) {
	return readInput(fsys, path, false)
}

// readDiffInput applies Diff's input rules to one path: an empty path, a
// missing file and a file with only whitespace (an empty file, or /dev/null
// standing in for the absent side of an added or removed file) have no
// functions (nil content, nil error); any other stat or read error, or a
// file over models.MaxSourceFileSize, is an error.
func readDiffInput(fsys FileSystem, path string) (content []byte, abs string, err error) {
	if path == "" {
		return nil, "", nil
	}
	return readInput(fsys, path, true)
}

// readInput reads the file at path. With absentOK, a missing file and a file
// with only whitespace have nil content and no error; otherwise they are
// errors. abs is the file's absolute path, which the loader reports its
// functions under: from the FileSystem, or from the working directory when
// the FileSystem gives no absolute path.
func readInput(fsys FileSystem, path string, absentOK bool) (content []byte, abs string, err error) {
	info, err := fsys.Stat(path)
	if err != nil {
		if absentOK && os.IsNotExist(err) {
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
		if absentOK {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("%s: input source code is empty", path)
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
func fingerprintGroup(files []pendingFile, strict bool) map[string]FileFingerprints {
	out := make(map[string]FileFingerprints)
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
		results, err = fingerprintPackagesSafely(wellTyped, paths.keepFiles(abs...), strict)
	}
	for _, f := range files {
		if err != nil || !diff.PackagesContain(wellTyped, f.abs) {
			out[f.path] = fingerprintOne(f, strict)
			continue
		}
		out[f.path] = FileFingerprints{Results: inFileOf(results, f.abs, packagesOf(wellTyped, f.abs), paths)}
	}
	return out
}

// fingerprintPackagesSafely fingerprints the functions of pkgs in the
// files keep accepts, turning a panic into an error.
func fingerprintPackagesSafely(pkgs []*packages.Package, keep func(string) bool, strict bool) (results []diff.FingerprintResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic while fingerprinting: %v", r)
		}
	}()
	return fingerprintPackages(pkgs, ir.DefaultLiteralPolicy, strict, keep)
}

// fingerprintOne loads and fingerprints one file on its own, as Diff does.
func fingerprintOne(f pendingFile, strict bool) (res FileFingerprints) {
	defer func() {
		if r := recover(); r != nil {
			res = FileFingerprints{Err: fmt.Errorf("panic while fingerprinting %s: %v", f.path, r)}
		}
	}()
	paths := pathResolver{}
	results, err := fingerprintSource(f.abs, string(f.content), ir.DefaultLiteralPolicy, strict, paths.keepFiles(f.abs))
	if err != nil {
		return FileFingerprints{Err: err}
	}
	return FileFingerprints{Results: inFile(results, f.abs, paths)}
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
