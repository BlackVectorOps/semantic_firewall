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
	"strconv"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff/internal/purge"
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
//   - their function bodies, and the contents of composite literals other
//     than [...]T arrays, are removed from the source before parsing
//     (purge.PurgeFuncBodies) and are not type-checked;
//   - they have no Syntax or TypesInfo, so SSA treats them like packages
//     loaded from export data;
//   - a dependency whose module version, files, build configuration and
//     transitive imports are all the same as in an earlier load of this
//     process (the standard library, an unchanged third-party module)
//     reuses that load's *types.Package.
//
// Because they are not checked, an error confined to a dependency's
// function bodies or composite literals no longer makes the roots
// ill-typed; and len or cap of a sized array literal whose elements made it
// non-constant becomes constant, which can fail a constant check. All
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
		store:     activeTypeStore(),
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
	// Dependency keys need only metadata: compute them all, imports first.
	packages.Visit(roots, nil, func(p *packages.Package) {
		if !l.roots[p] && p.PkgPath != "unsafe" {
			l.state[p].key = l.dependencyKey(p)
		}
	})
	if l.store != nil {
		l.prepareStored(roots)
	}
	l.parseAhead(roots)
	var wg sync.WaitGroup
	for _, r := range roots {
		wg.Add(1)
		go func(p *packages.Package) {
			defer wg.Done()
			l.load(p)
		}(r)
	}
	wg.Wait()
	l.prefetches.Wait()
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
	// For a package go list cannot load (a module missing from the
	// cache), go/packages takes a file from the error's position only when
	// the error's import stack ends at the package, and the stack depends
	// on the run's patterns. The per-file runs list such a graph as
	// go/packages does.
	listErr := false
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			listErr = listErr || e.Kind == packages.ListError
		}
	})
	if listErr {
		return listPackages(meta, patterns...)
	}
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
	// store is the persistent type cache, or nil; prefetches counts the
	// entries prepareStored is reading.
	store      *typeStore
	prefetches sync.WaitGroup
	overlay    map[string][]byte
	roots      map[*packages.Package]bool
	state      map[*packages.Package]*loadState

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
	// decls and need are a dependency's parse and needed imports when it
	// is not shareable.
	decls parsedDeclarations
	need  neededPaths
}

type parsedFile struct {
	ready chan struct{}
	file  *ast.File
	err   error
}

// parseAhead starts parsing the roots' files: parsing needs no types, so
// it need not wait, as type-checking does, until the imports are checked.
// A dependency is parsed as soon as a load needs it (see neededImports).
func (l *sourceLoader) parseAhead(roots []*packages.Package) {
	for _, p := range roots {
		if p.PkgPath != "unsafe" {
			for _, name := range p.CompiledGoFiles {
				go l.parseRoot(name)
			}
		}
	}
}

// neededImports returns the import paths a check of the dependency p
// needs: those its declarations name (see declaredImports). The packages
// it imports only for its function bodies are not loaded at all. A
// shared dependency's cache entry records them; otherwise p is parsed for
// them, once.
func (l *sourceLoader) neededImports(p *packages.Package) []string {
	st := l.state[p]
	need, decls := &st.need, &st.decls
	if st.key != "" {
		e := depCache.entry(st.key)
		need, decls = &e.need, &e.decls
	}
	need.once.Do(func() {
		if st.key != "" && l.store != nil && len(p.Errors) == 0 {
			l.fetchStored(p)
			if stored := l.storedOf(p); stored.payload != nil {
				need.paths = stored.needed
				return
			}
		}
		decls.parse(l, p)
		need.paths = declaredImports(p, decls.syntax)
	})
	return need.paths
}

// neededView returns, by path, the packages the check of the dependency p
// depends on: its needed imports, theirs, and so on. The load of p waited
// for each, and no other: another package of the load may be checking
// right now one that p imports only for its bodies.
func (l *sourceLoader) neededView(p *packages.Package) map[string]*types.Package {
	view := make(map[string]*types.Package)
	var walk func(q *packages.Package)
	walk = func(q *packages.Package) {
		for _, path := range l.neededImports(q) {
			imp := q.Imports[path]
			if _, seen := view[imp.PkgPath]; seen || imp.PkgPath == "unsafe" {
				continue
			}
			view[imp.PkgPath] = imp.Types
			walk(imp)
		}
	}
	walk(p)
	return view
}

// neededPaths is the paths neededImports returns for a package, once.
type neededPaths struct {
	once  sync.Once
	paths []string
}

// declaredImports returns, sorted, the paths of p's imports that its
// files, parsed with function bodies purged, can use: those whose name
// appears as an identifier outside the import declarations, dot imports,
// and imports whose package has no name. With the bodies gone, any other
// import serves the bodies only. A blank import declares no name.
func declaredImports(p *packages.Package, files []*ast.File) []string {
	used := make(map[string]struct{})
	for _, f := range files {
		names := make(map[string]bool)
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				names[id.Name] = true
			}
			_, spec := n.(*ast.ImportSpec)
			return !spec
		})
		for _, spec := range f.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			imp := p.Imports[path]
			if imp == nil {
				continue // not an import go list resolved; pruneImports keeps it
			}
			name := imp.Name
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "." || name == "" || name != "_" && names[name] {
				used[path] = struct{}{}
			}
		}
	}
	paths := make([]string, 0, len(used))
	for path := range used {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// pruneImports removes from files the declarations of p's imports outside
// needed: no declaration names them, and the check, which skips function
// bodies, then needs no types for them. Declarations of anything else go
// list did not resolve stay, for the check to report.
func pruneImports(p *packages.Package, files []*ast.File, needed []string) {
	keep := make(map[string]bool, len(needed))
	for _, path := range needed {
		keep[path] = true
	}
	for _, f := range files {
		decls := f.Decls[:0]
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
				specs := gd.Specs[:0]
				for _, s := range gd.Specs {
					path, _ := strconv.Unquote(s.(*ast.ImportSpec).Path.Value)
					if keep[path] || p.Imports[path] == nil {
						specs = append(specs, s)
					}
				}
				gd.Specs = specs
				// An import declaration without specs has no end
				// (ast.GenDecl.End): drop it.
				if len(specs) == 0 {
					continue
				}
			}
			decls = append(decls, d)
		}
		f.Decls = decls
	}
}

// prepareStored computes the persistent cache key of every shared
// dependency and reads its entry, starting to parse the dependency when
// there is none: first every file's digest, at once, then the keys, then
// every entry, at once. Only decoding an entry waits,
// as type-checking does, until the package's imports are loaded.
func (l *sourceLoader) prepareStored(roots []*packages.Package) {
	var shared []*packages.Package
	packages.Visit(roots, nil, func(p *packages.Package) {
		if !l.roots[p] && l.state[p].key != "" && len(p.Errors) == 0 {
			shared = append(shared, p)
		}
	})
	var wg sync.WaitGroup
	for _, p := range shared {
		wg.Add(1)
		go func(p *packages.Package) {
			defer wg.Done()
			l.digestStored(p)
		}(p)
	}
	wg.Wait()
	for _, p := range shared {
		l.keyStored(p)
	}
	// Some of these packages no load may need; the load still waits for
	// every read before it returns.
	for _, p := range shared {
		l.prefetches.Add(1)
		go func(p *packages.Package) {
			defer l.prefetches.Done()
			l.fetchStored(p)
		}(p)
	}
}

// storedOf returns the persistent cache state of the shared dependency p.
func (l *sourceLoader) storedOf(p *packages.Package) *persisted {
	return &depCache.entry(l.state[p].key).stored
}

// digestStored hashes p's files, once.
func (l *sourceLoader) digestStored(p *packages.Package) {
	st := l.storedOf(p)
	st.digestOnce.Do(func() {
		cpuTokens <- struct{}{}
		st.digests = l.store.digests(p)
		<-cpuTokens
	})
}

// keyStored computes p's key, once, from its imports' keys. A package go
// list reports errors for has none.
func (l *sourceLoader) keyStored(p *packages.Package) {
	st := l.storedOf(p)
	st.keyOnce.Do(func() {
		l.digestStored(p)
		st.key = l.store.key(p, st.digests, func(imp *packages.Package) string {
			if len(imp.Errors) > 0 {
				return ""
			}
			l.keyStored(imp)
			return l.storedOf(imp).key
		})
	})
}

// fetchStored reads p's entry, once. An entry naming an import p does not
// have is a miss.
func (l *sourceLoader) fetchStored(p *packages.Package) {
	st := l.storedOf(p)
	st.fetchOnce.Do(func() {
		l.keyStored(p)
		if st.key == "" {
			return
		}
		needed, payload := l.store.read(st.key)
		for _, path := range needed {
			if p.Imports[path] == nil {
				return
			}
		}
		st.needed, st.payload = needed, payload
	})
}

// load type-checks p after the imports its check needs, once: a root's
// every import, a dependency's needed imports.
func (l *sourceLoader) load(p *packages.Package) {
	st := l.state[p]
	st.once.Do(func() {
		var imports []*packages.Package
		if l.roots[p] {
			for _, imp := range p.Imports {
				imports = append(imports, imp)
			}
		} else {
			for _, path := range l.neededImports(p) {
				imports = append(imports, p.Imports[path])
			}
		}
		var wg sync.WaitGroup
		for _, imp := range imports {
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
		p.IllTyped = len(p.Errors) > 0 || anyIllTyped(imports)

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
	if st.key == "" {
		l.checkDeclarations(p, &st.decls, l.neededImports(p))
		return
	}
	// One computation per key: every load uses the same *types.Package for
	// a key, so a reused package and the imports it was checked against are
	// the same objects as this load's. The persistent type cache holds only
	// packages that, like their imports, have no errors, so one go list
	// reports errors for is checked.
	listErrors := len(p.Errors)
	needed := l.neededImports(p)
	c := depCache.do(st.key, func(e *cacheEntry) cachedPackage {
		if l.store != nil && listErrors == 0 {
			l.fetchStored(p)
			if e.stored.payload != nil {
				t := decode(e.stored.payload, p, l.neededView(p))
				e.stored.payload = nil
				if t != nil {
					l.store.hits.Add(1)
					return cachedPackage{types: t}
				}
			}
			l.store.misses.Add(1)
		}
		l.checkDeclarations(p, &e.decls, needed)
		if l.store != nil && listErrors == 0 && e.stored.key != "" && len(p.Errors) == 0 && !anyIllTyped(neededPackages(p, needed)) {
			l.store.save(e.stored.key, needed, p.Types)
		}
		return cachedPackage{types: p.Types, errors: append([]packages.Error(nil), p.Errors[listErrors:]...)}
	})
	p.Types = c.types
	p.Errors = append(p.Errors[:listErrors], c.errors...)
}

// anyIllTyped reports whether any of pkgs is ill-typed. A package checked
// against one is ill-typed too, though go/types reports no error for its
// uses of the invalid types, and is not stored.
func anyIllTyped(pkgs []*packages.Package) bool {
	for _, p := range pkgs {
		if p.IllTyped {
			return true
		}
	}
	return false
}

// neededPackages returns p's imports at paths.
func neededPackages(p *packages.Package, paths []string) []*packages.Package {
	out := make([]*packages.Package, len(paths))
	for i, path := range paths {
		out[i] = p.Imports[path]
	}
	return out
}

// checkDeclarations type-checks a dependency's declarations, from its
// files parsed with their bodies purged, against its needed imports.
func (l *sourceLoader) checkDeclarations(p *packages.Package, decls *parsedDeclarations, needed []string) {
	syntax, errs := decls.take(l, p)
	for _, err := range errs {
		appendLoadError(p, err)
	}
	pruneImports(p, syntax, needed)
	p.Types = types.NewPackage(p.PkgPath, p.Name)
	l.typeCheck(p, syntax, nil, true)
}

// parsedDeclarations is a dependency's files parsed once, with their
// function bodies purged, and the errors reading and parsing them gave.
// neededImports parses them, and checkDeclarations takes them.
type parsedDeclarations struct {
	once   sync.Once
	syntax []*ast.File
	errs   []error
}

// parse parses p's files, unless they are parsed already. Every package
// that shares the parse has the same files with the same contents.
func (d *parsedDeclarations) parse(l *sourceLoader, p *packages.Package) {
	d.once.Do(func() {
		for _, name := range p.CompiledGoFiles {
			src, err := l.readFile(name)
			if err != nil {
				d.errs = append(d.errs, err)
				continue
			}
			cpuTokens <- struct{}{}
			// Given the source, ParseFile returns a file even when it fails.
			f, err := parser.ParseFile(sharedFset, name, purge.PurgeFuncBodies(src), parser.SkipObjectResolution)
			<-cpuTokens
			if err != nil {
				d.errs = append(d.errs, err)
			}
			d.syntax = append(d.syntax, f)
		}
	})
}

// take returns the parse, parsing first if no one has, and lets go of it:
// a dependency's syntax is not kept once its declarations are checked.
func (d *parsedDeclarations) take(l *sourceLoader, p *packages.Package) ([]*ast.File, []error) {
	d.parse(l, p)
	syntax, errs := d.syntax, d.errs
	d.syntax, d.errs = nil, nil
	return syntax, errs
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

// readSourceFile is os.ReadFile; tests make it fail.
var readSourceFile = os.ReadFile

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
	return readSourceFile(name)
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

// cacheEntry is one key's package: the parse its computation starts from,
// its place in the persistent type cache, and the computed value.
type cacheEntry struct {
	decls  parsedDeclarations
	need   neededPaths
	stored persisted
	once   sync.Once
	value  cachedPackage
}

// persisted is a shared package's place in the persistent type cache,
// each part computed once: its files' digests, its key ("" when it has
// none), and its entry: the needed imports it records and its payload
// until decoded (nil on a miss).
type persisted struct {
	digestOnce sync.Once
	digests    [][sha256.Size]byte
	keyOnce    sync.Once
	key        string
	fetchOnce  sync.Once
	needed     []string
	payload    []byte
}

// entry returns key's entry, adding it if there is none.
func (c *packageCache) entry(key string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		e = &cacheEntry{}
		c.m[key] = e
	}
	return e
}

// do returns the value cached for key, computing it with compute if no
// load has: concurrent callers for one key wait for a single computation.
func (c *packageCache) do(key string, compute func(*cacheEntry) cachedPackage) cachedPackage {
	e := c.entry(key)
	e.once.Do(func() { e.value = compute(e) })
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
