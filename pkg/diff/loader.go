package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff/internal/purge"
)

// LoaderEnvVar selects the source loader. Set to "packages" it makes every
// source load a plain go/packages LoadAllSyntax load, which type-checks
// every dependency's function bodies; any other value selects the faster
// loader (see loadSource).
const LoaderEnvVar = "SFW_LOADER"

// loadSource loads patterns with the semantics of packages.Load(cfg) in
// LoadAllSyntax mode for the packages the patterns match (the roots):
// the same go list invocation (cfg's Dir, Env, BuildFlags, Overlay and
// Tests), the same parse mode and type-checker configuration, the same
// errors and the same IllTyped propagation. Dependencies differ in three
// ways, none of which is visible through the roots' syntax or types:
//
//   - their function bodies are removed from the source before parsing
//     (purge.PurgeFuncBodies) and are not type-checked;
//   - they have no Syntax or TypesInfo, so SSA treats them like packages
//     loaded from export data;
//   - a dependency whose module version, files, build configuration and
//     transitive imports are all the same as in an earlier load of this
//     process (the standard library, an unchanged third-party module)
//     reuses that load's *types.Package.
//
// Because dependency bodies are not checked, an error confined to a
// dependency's function bodies no longer makes the roots ill-typed. All
// loads share one token.FileSet, so packages reused across loads keep
// valid positions.
func loadSource(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
	if os.Getenv(LoaderEnvVar) == "packages" {
		return packages.Load(cfg, patterns...)
	}
	meta := *cfg
	meta.Mode = packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedImports | packages.NeedDeps | packages.NeedModule | packages.NeedTypesSizes
	meta.Fset = nil
	roots, err := loadMetadata(&meta, patterns)
	if err != nil {
		return nil, err
	}
	l := &sourceLoader{
		overlay:   cfg.Overlay,
		roots:     make(map[*packages.Package]bool, len(roots)),
		state:     make(map[*packages.Package]*loadState),
		rootFiles: make(map[string]*parsedFile),
	}
	for _, r := range roots {
		l.roots[r] = true
	}
	packages.Visit(roots, nil, func(p *packages.Package) {
		l.state[p] = &loadState{}
	})
	if hasImportCycle(roots) {
		// go list reports cycles as errors; never risk waiting on one.
		return packages.Load(cfg, patterns...)
	}
	var wg sync.WaitGroup
	for _, r := range roots {
		wg.Add(1)
		go func(p *packages.Package) {
			defer wg.Done()
			l.load(p)
		}(r)
	}
	wg.Wait()
	return roots, nil
}

// listPackages is packages.Load; tests record its calls.
var listPackages = packages.Load

// loadMetadata returns what packages.Load(meta, patterns...) returns, but
// answers several file= queries for absolute paths, as LoadFiles makes,
// with one go list run. go/packages runs go list once per file= query, each
// over the file's directory and every package it depends on (its own TODO:
// "Do only one query per directory"), so a batch of n files paid for n full
// listings. Here one run lists every query's directory, and each query's
// roots are picked as go/packages picks them: the packages listed for the
// file's directory with a Go file of the file's base name, in query order.
// Where go/packages would instead build an ad-hoc package (go list listed
// nothing for the directory, or a package without Go files), the per-file
// load decides.
func loadMetadata(meta *packages.Config, patterns []string) ([]*packages.Package, error) {
	if len(patterns) < 2 {
		return listPackages(meta, patterns...)
	}
	dirs := make([]string, len(patterns))
	var listed []string
	seen := make(map[string]bool)
	for i, pattern := range patterns {
		query, file, _ := strings.Cut(pattern, "=")
		if query != "file" || !filepath.IsAbs(file) {
			return listPackages(meta, patterns...)
		}
		dirs[i] = filepath.Dir(file)
		if !seen[dirs[i]] {
			seen[dirs[i]] = true
			// "pattern=" passes the directory to go list verbatim, as a
			// file= query passes it.
			listed = append(listed, "pattern="+dirs[i])
		}
	}
	// A run that fails lists no package, so every query takes the per-file
	// load below, which reports the failure.
	pkgs, _ := listPackages(meta, listed...)
	inDir := make(map[string][]*packages.Package)
	for _, p := range pkgs {
		inDir[p.Dir] = append(inDir[p.Dir], p)
	}
	var roots []*packages.Package
	added := make(map[*packages.Package]bool)
	for i, pattern := range patterns {
		if len(inDir[dirs[i]]) == 0 {
			return listPackages(meta, patterns...)
		}
		base := filepath.Base(pattern) // "file=" and an absolute path
		for _, p := range inDir[dirs[i]] {
			if len(p.GoFiles) == 0 {
				return listPackages(meta, patterns...)
			}
			for _, f := range p.GoFiles {
				if filepath.Base(f) == base && !added[p] {
					added[p] = true
					roots = append(roots, p)
				}
			}
		}
	}
	return roots, nil
}

// sharedFset holds the positions of every package loadSource parses.
var sharedFset = token.NewFileSet()

// cpuTokens bounds concurrent parsing and type-checking.
var cpuTokens = make(chan struct{}, runtime.GOMAXPROCS(0))

type sourceLoader struct {
	overlay map[string][]byte
	roots   map[*packages.Package]bool
	state   map[*packages.Package]*loadState

	// rootFiles caches root parses by filename: a file compiled into two
	// roots (a package and its test variant) is parsed once, as
	// go/packages does.
	rootMu    sync.Mutex
	rootFiles map[string]*parsedFile
}

type loadState struct {
	once sync.Once
	// key identifies a shareable dependency; "" when it may not be reused.
	key string
}

type parsedFile struct {
	ready chan struct{}
	file  *ast.File
	err   error
}

// load type-checks p after its imports, once.
func (l *sourceLoader) load(p *packages.Package) {
	st := l.state[p]
	st.once.Do(func() {
		var wg sync.WaitGroup
		for _, imp := range p.Imports {
			wg.Add(1)
			go func(imp *packages.Package) {
				defer wg.Done()
				l.load(imp)
			}(imp)
		}
		wg.Wait()
		p.Fset = sharedFset
		if p.PkgPath == "unsafe" {
			p.Types = types.Unsafe
			p.Syntax = []*ast.File{}
			p.TypesInfo = new(types.Info)
			return
		}
		if l.roots[p] {
			l.checkRoot(p)
		} else {
			l.checkDependency(p, st)
		}
		p.IllTyped = len(p.Errors) > 0
		if !p.IllTyped {
			for _, imp := range p.Imports {
				if imp.IllTyped {
					p.IllTyped = true
					break
				}
			}
		}
	})
}

// checkRoot parses and type-checks a root exactly as go/packages does in
// LoadAllSyntax mode.
func (l *sourceLoader) checkRoot(p *packages.Package) {
	files := make([]*ast.File, len(p.CompiledGoFiles))
	errs := make([]error, len(p.CompiledGoFiles))
	var wg sync.WaitGroup
	for i, name := range p.CompiledGoFiles {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			files[i], errs[i] = l.parseRoot(name)
		}(i, name)
	}
	wg.Wait()
	var syntax []*ast.File
	for i := range files {
		if errs[i] != nil {
			appendLoadError(p, errs[i])
		}
		if files[i] != nil {
			syntax = append(syntax, files[i])
		}
	}
	p.Syntax = syntax
	p.TypesInfo = &types.Info{
		Types:        make(map[ast.Expr]types.TypeAndValue),
		Defs:         make(map[*ast.Ident]types.Object),
		Uses:         make(map[*ast.Ident]types.Object),
		Implicits:    make(map[ast.Node]types.Object),
		Instances:    make(map[*ast.Ident]types.Instance),
		Scopes:       make(map[ast.Node]*types.Scope),
		Selections:   make(map[*ast.SelectorExpr]*types.Selection),
		FileVersions: make(map[*ast.File]string),
	}
	p.Types = types.NewPackage(p.PkgPath, p.Name)
	l.typeCheck(p, p.Syntax, p.TypesInfo, false)
}

func (l *sourceLoader) parseRoot(name string) (*ast.File, error) {
	l.rootMu.Lock()
	pf, ok := l.rootFiles[name]
	if !ok {
		pf = &parsedFile{ready: make(chan struct{})}
		l.rootFiles[name] = pf
	}
	l.rootMu.Unlock()
	if ok {
		<-pf.ready
		return pf.file, pf.err
	}
	defer close(pf.ready)
	src, err := l.readFile(name)
	if err != nil {
		pf.err = err
		return nil, err
	}
	cpuTokens <- struct{}{}
	pf.file, pf.err = parser.ParseFile(sharedFset, name, src, parser.AllErrors|parser.ParseComments)
	<-cpuTokens
	return pf.file, pf.err
}

// checkDependency type-checks a dependency's declarations only, or reuses
// an identical earlier load.
func (l *sourceLoader) checkDependency(p *packages.Package, st *loadState) {
	st.key = l.dependencyKey(p)
	if st.key == "" {
		l.checkDeclarations(p)
		return
	}
	// One computation per key: every load uses the same *types.Package for
	// a key, so a reused package and the imports it was checked against are
	// the same objects as this load's.
	listErrors := len(p.Errors)
	c := depCache.do(st.key, func() cachedPackage {
		l.checkDeclarations(p)
		return cachedPackage{types: p.Types, errors: append([]packages.Error(nil), p.Errors[listErrors:]...)}
	})
	p.Types = c.types
	p.Errors = append(p.Errors[:listErrors], c.errors...)
}

// checkDeclarations parses a dependency with its bodies purged and
// type-checks its declarations.
func (l *sourceLoader) checkDeclarations(p *packages.Package) {
	var syntax []*ast.File
	for _, name := range p.CompiledGoFiles {
		src, err := l.readFile(name)
		if err != nil {
			appendLoadError(p, err)
			continue
		}
		cpuTokens <- struct{}{}
		f, err := parser.ParseFile(sharedFset, name, purge.PurgeFuncBodies(src), parser.SkipObjectResolution)
		<-cpuTokens
		if err != nil {
			appendLoadError(p, err)
		}
		if f != nil {
			syntax = append(syntax, f)
		}
	}
	p.Types = types.NewPackage(p.PkgPath, p.Name)
	l.typeCheck(p, syntax, nil, true)
}

// typeCheck runs the type checker with go/packages' configuration.
func (l *sourceLoader) typeCheck(p *packages.Package, files []*ast.File, info *types.Info, ignoreBodies bool) {
	importer := importerFunc(func(path string) (*types.Package, error) {
		if path == "unsafe" {
			return types.Unsafe, nil
		}
		ipkg := p.Imports[path]
		if ipkg == nil {
			return nil, fmt.Errorf("no metadata for %s", path)
		}
		if ipkg.Types == nil || !ipkg.Types.Complete() {
			return nil, fmt.Errorf("no types for %s", path)
		}
		return ipkg.Types, nil
	})
	tc := &types.Config{
		Importer:         importer,
		IgnoreFuncBodies: ignoreBodies,
		Error:            func(err error) { appendLoadError(p, err) },
		Sizes:            p.TypesSizes,
	}
	if p.Module != nil && p.Module.GoVersion != "" {
		tc.GoVersion = "go" + p.Module.GoVersion
	}
	cpuTokens <- struct{}{}
	typErr := types.NewChecker(tc, sharedFset, p.Types, info).Files(files)
	<-cpuTokens
	// go/types reports every error through tc.Error, so this never fires;
	// like go/packages, keep it so an unreported error still makes the
	// package ill-typed.
	if typErr != nil && len(p.Errors) == 0 {
		appendLoadError(p, typErr)
	}
}

// readFile reads a compiled Go file, preferring its overlay.
func (l *sourceLoader) readFile(name string) ([]byte, error) {
	if src, ok := l.overlay[name]; ok {
		return src, nil
	}
	for f, src := range l.overlay {
		if sameFile(f, name) {
			return src, nil
		}
	}
	return os.ReadFile(name)
}

func (l *sourceLoader) overlaid(name string) bool {
	if _, ok := l.overlay[name]; ok {
		return true
	}
	for f := range l.overlay {
		if sameFile(f, name) {
			return true
		}
	}
	return false
}

// dependencyKey identifies a dependency whose types can be shared with
// other loads of this process, or returns "". A package is shareable when
// its files cannot change during the process: it is from the standard
// library or from a module at a fixed version in the module cache (not
// the main module, not a local directory replacement), none of its files
// is overlaid, and it imports only shareable packages. The key hashes
// exactly the inputs of checkDeclarations: the package path and name, the
// compiled file paths (whose contents are fixed), the keys of the imports,
// the type sizes and the Go version.
func (l *sourceLoader) dependencyKey(p *packages.Package) string {
	fixed := isStandardPackage(p) ||
		(p.Module != nil && !p.Module.Main && p.Module.Version != "" && (p.Module.Replace == nil || p.Module.Replace.Version != ""))
	if !fixed {
		return ""
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%#v\x00", p.PkgPath, p.Name, p.TypesSizes)
	if p.Module != nil {
		fmt.Fprintf(h, "go%s\x00", p.Module.GoVersion)
	}
	for _, f := range p.CompiledGoFiles {
		if l.overlaid(f) {
			return ""
		}
		fmt.Fprintf(h, "%s\x00", f)
	}
	paths := make([]string, 0, len(p.Imports))
	for path := range p.Imports {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		imp := p.Imports[path]
		if imp.PkgPath == "unsafe" {
			fmt.Fprintf(h, "%s=unsafe\x00", path)
			continue
		}
		ik := l.state[imp].key
		if ik == "" {
			return ""
		}
		fmt.Fprintf(h, "%s=%s\x00", path, ik)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// isStandardPackage reports whether p is a standard-library package (and
// not a test variant of one).
func isStandardPackage(p *packages.Package) bool {
	if p.Module != nil || p.ID != p.PkgPath {
		return false
	}
	first, _, _ := strings.Cut(p.PkgPath, "/")
	return !strings.Contains(first, ".") && p.PkgPath != "command-line-arguments"
}

type cachedPackage struct {
	types  *types.Package
	errors []packages.Error
}

// depCache holds the shareable dependencies loaded by this process.
var depCache = &packageCache{m: make(map[string]*cacheEntry)}

type packageCache struct {
	mu sync.Mutex
	m  map[string]*cacheEntry
}

type cacheEntry struct {
	ready chan struct{}
	value cachedPackage
}

// do returns the value cached for key, computing it with compute if no
// load has: concurrent callers for one key wait for a single computation.
func (c *packageCache) do(key string, compute func() cachedPackage) cachedPackage {
	c.mu.Lock()
	e, ok := c.m[key]
	if !ok {
		e = &cacheEntry{ready: make(chan struct{})}
		c.m[key] = e
	}
	c.mu.Unlock()
	if ok {
		<-e.ready
		return e.value
	}
	defer close(e.ready)
	e.value = compute()
	return e.value
}

// appendLoadError converts an error the way go/packages does and records it.
func appendLoadError(p *packages.Package, err error) {
	switch err := err.(type) {
	case packages.Error:
		p.Errors = append(p.Errors, err)
	case *os.PathError:
		p.Errors = append(p.Errors, packages.Error{Pos: err.Path + ":1", Msg: err.Err.Error(), Kind: packages.ParseError})
	case scanner.ErrorList:
		for _, e := range err {
			p.Errors = append(p.Errors, packages.Error{Pos: e.Pos.String(), Msg: e.Msg, Kind: packages.ParseError})
		}
	case types.Error:
		p.TypeErrors = append(p.TypeErrors, err)
		p.Errors = append(p.Errors, packages.Error{Pos: err.Fset.Position(err.Pos).String(), Msg: err.Msg, Kind: packages.TypeError})
	default:
		p.Errors = append(p.Errors, packages.Error{Pos: "-", Msg: err.Error(), Kind: packages.UnknownError})
	}
}

// hasImportCycle reports whether the import graph under roots has a cycle.
func hasImportCycle(roots []*packages.Package) bool {
	const (
		white = iota
		grey
		black
	)
	color := make(map[*packages.Package]int)
	var visit func(p *packages.Package) bool
	visit = func(p *packages.Package) bool {
		switch color[p] {
		case grey:
			return true
		case black:
			return false
		}
		color[p] = grey
		for _, imp := range p.Imports {
			if visit(imp) {
				return true
			}
		}
		color[p] = black
		return false
	}
	for _, r := range roots {
		if visit(r) {
			return true
		}
	}
	return false
}

// sameFile reports whether x and y name the same file, as go/packages
// decides it for overlays.
func sameFile(x, y string) bool {
	if x == y {
		return true
	}
	if strings.EqualFold(filepath.Base(x), filepath.Base(y)) {
		if xi, err := os.Stat(x); err == nil {
			if yi, err := os.Stat(y); err == nil {
				return os.SameFile(xi, yi)
			}
		}
	}
	return false
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
