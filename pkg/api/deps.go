package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

// Risk charged for changes to code the SSA analysis cannot see. A new or
// changed .syso or other object file links precompiled machine code into the
// binary, and a new //go:linkname directive reaches into another package's
// internals; both are high-risk. Other unanalyzed changes are reported below the threshold.
const (
	riskUnanalyzedSyso     = 20
	riskUnanalyzedLinkname = models.RiskScoreHigh
	riskUnanalyzedOther    = 5
	// riskInitReach is added when a package initializer, which runs on
	// import, newly reaches a capability.
	riskInitReach = models.RiskScoreHigh
)

// DepsDiff compares the third-party code compiled into the module rooted at
// oldDir with that compiled into the module rooted at newDir. Both trees are
// loaded with the hardened loader environment (GOPROXY=off), so every module
// either build needs must already be in the module cache.
//
// A module is compared when its version or replacement differs between the
// trees, or when its code can change without either: replaced by a local
// directory, a module of the go.work that governs the tree (the go command
// builds with it; see diff.WorkspaceFile), or vendored (a tree with
// vendor/modules.txt is loaded from its vendor directory, as the go command
// builds it). For each such module the
// diff reports changed functions (paired and scored as in Diff), exported
// functions and package initializers that newly reach a capability class,
// and changes to files the analysis cannot see. Modules only in the new
// tree, and packages the new tree newly builds from an unchanged module,
// are reported with the capability classes their exported functions and
// initializers can reach.
func DepsDiff(oldDir, newDir string) (*models.DepsDiffOutput, error) {
	oldSide, err := loadDepsSide(oldDir)
	if err != nil {
		return nil, fmt.Errorf("old tree: %w", err)
	}
	newSide, err := loadDepsSide(newDir)
	if err != nil {
		return nil, fmt.Errorf("new tree: %w", err)
	}

	out := &models.DepsDiffOutput{OldDir: oldDir, NewDir: newDir, Modules: []models.ModuleDiff{}}
	paths := make(map[string]struct{})
	for p := range oldSide.modules {
		paths[p] = struct{}{}
	}
	for p := range newSide.modules {
		paths[p] = struct{}{}
	}
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		om, nm := oldSide.modules[path], newSide.modules[path]
		var md models.ModuleDiff
		switch {
		case om == nil:
			md = newSide.describe(nm, nm.pkgs, models.ModuleAdded, nil)
			out.Summary.ModulesAdded++
		case nm == nil:
			md = models.ModuleDiff{Path: path, Status: models.ModuleRemoved, OldVersion: om.identity}
			out.Summary.ModulesRemoved++
		case om.identity == nm.identity && !om.localReplace && !om.vendored && !nm.vendored:
			// The same release, from the module cache: only packages the new
			// tree newly builds are new code.
			added := newPackages(om, nm)
			if len(added) == 0 {
				continue
			}
			md = newSide.describe(nm, added, models.ModuleUpdated, om)
			md.OldVersion = om.identity
			out.Summary.ModulesUpdated++
		default:
			md = diffModule(oldSide, newSide, om, nm)
			if len(md.Packages) == 0 && len(md.Reach) == 0 && len(md.Unanalyzed) == 0 && om.identity == nm.identity {
				continue // a local replacement whose content did not change
			}
			out.Summary.ModulesUpdated++
		}
		for _, p := range md.Packages {
			out.Summary.FunctionsChanged += len(p.Functions)
		}
		out.Summary.HighRiskChanges += md.HighRiskChanges
		out.Modules = append(out.Modules, md)
	}
	return out, nil
}

// workspacePath names the directory of a workspace module as the go.work
// at work names it: relative to the go.work's directory, so the same
// layout reads the same in both trees.
func workspacePath(work, dir string) string {
	rel, _ := filepath.Rel(filepath.Dir(work), dir) // both are absolute
	rel = filepath.ToSlash(rel)
	if !strings.HasPrefix(rel, "../") && rel != ".." {
		rel = "./" + rel
	}
	return rel
}

// depsSide is one tree's build: the SSA of its whole import graph, with the
// third-party packages built, grouped by module.
type depsSide struct {
	prog    *ssa.Program
	modules map[string]*depModule

	// callees and direct cache, per function, the functions it references
	// and the capability call targets it references directly; reached
	// caches reach.
	callees map[*ssa.Function][]*ssa.Function
	direct  map[*ssa.Function]map[string]string
	reached map[*ssa.Function]map[string]string
	scc     sccState
}

type depModule struct {
	path string
	// identity is the version, or the replacement, the build uses.
	identity     string
	localReplace bool
	// vendored is set when the tree builds the module from its vendor
	// directory, whose content can change without a version change.
	vendored bool
	dir      string
	pkgs     []*packages.Package
}

func loadDepsSide(dir string) (*depsSide, error) {
	// The build follows the go.work that governs dir, as the go command's
	// does. Its other modules are code the module did not write: each is
	// compared like a module replaced by a local directory, so a `use` of
	// a directory that takes a dependency's path shows as that dependency
	// replaced.
	env := diff.HardenedEnvFor(dir)
	work := diff.WorkspaceFile(dir)
	// The go command builds with a consistent vendor directory, the
	// module's or, in a workspace, the workspace's (go work vendor),
	// rather than the module cache; so does the analysis.
	vendorRoot := dir
	if work != "" {
		vendorRoot = filepath.Dir(work)
	}
	_, statErr := os.Stat(filepath.Join(vendorRoot, "vendor", "modules.txt"))
	vendored := statErr == nil
	if vendored {
		env = append(env, "GOFLAGS=-mod=vendor") // the last value of a variable wins
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
			packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo |
			packages.NeedModule | packages.NeedEmbedFiles,
		Dir:  dir,
		Env:  env,
		Fset: token.NewFileSet(),
	}
	roots, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", dir, err)
	}
	var errs []string
	packages.Visit(roots, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			errs = append(errs, e.Error())
		}
	})
	if len(errs) > 0 {
		if len(errs) > 5 {
			errs = append(errs[:5], fmt.Sprintf("... and %d more", len(errs)-5))
		}
		return nil, fmt.Errorf("loading %s (run `go mod download` there first if modules are missing):\n  %s", dir, strings.Join(errs, "\n  "))
	}

	own := make(map[string]bool)
	for _, p := range roots {
		if p.Module != nil {
			own[p.Module.Path] = true
		}
	}
	side := &depsSide{
		modules: make(map[string]*depModule),
		callees: make(map[*ssa.Function][]*ssa.Function),
		direct:  make(map[*ssa.Function]map[string]string),
		reached: make(map[*ssa.Function]map[string]string),
	}
	var thirdParty []*packages.Package
	packages.Visit(roots, nil, func(p *packages.Package) {
		if p.Module == nil || own[p.Module.Path] {
			return
		}
		thirdParty = append(thirdParty, p)
		m := side.modules[p.Module.Path]
		if m == nil {
			// Module.Dir is the replacement's directory for a replaced module.
			m = &depModule{path: p.Module.Path, identity: p.Module.Version, dir: p.Module.Dir}
			if r := p.Module.Replace; r != nil {
				if r.Version != "" {
					m.identity = r.Path + "@" + r.Version
				} else {
					m.identity, m.localReplace = "replace "+r.Path, true
				}
			} else if p.Module.Main {
				m.identity, m.localReplace = "use "+workspacePath(work, p.Module.Dir), true
			}
			if vendored {
				m.vendored, m.dir = true, filepath.Join(vendorRoot, "vendor", filepath.FromSlash(p.Module.Path))
			}
			side.modules[p.Module.Path] = m
		}
		m.pkgs = append(m.pkgs, p)
	})

	var buildErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				buildErr = fmt.Errorf("SSA construction for %s panicked: %v", dir, r)
			}
		}()
		side.prog, _ = ssautil.AllPackages(roots, ssa.InstantiateGenerics)
		for _, p := range thirdParty {
			side.prog.Package(p.Types).Build()
		}
	}()
	if buildErr != nil {
		return nil, buildErr
	}
	return side, nil
}

// diffModule compares one module present in both trees.
func diffModule(oldSide, newSide *depsSide, om, nm *depModule) models.ModuleDiff {
	md := models.ModuleDiff{Path: nm.path, Status: models.ModuleUpdated, OldVersion: om.identity, NewVersion: nm.identity}

	oldPkgs, newPkgs := packagesByPath(om), packagesByPath(nm)
	for _, path := range unionKeys(oldPkgs, newPkgs) {
		oldRes := oldSide.fingerprintPackage(oldPkgs[path])
		newRes := newSide.fingerprintPackage(newPkgs[path])
		d := diffResults(path, path, oldRes, newRes, riskProfile{ownModule: nm.path, labelGoroutines: true})
		var changed []models.FunctionDiff
		for _, f := range d.Functions {
			if f.Status != models.StatusPreserved {
				changed = append(changed, f)
			}
		}
		if len(changed) == 0 {
			continue
		}
		md.Packages = append(md.Packages, models.PackageDiff{Path: path, Summary: d.Summary, Functions: changed})
		for _, f := range changed {
			noteRisk(&md, f.RiskScore)
		}
	}

	oldEntries, newEntries := oldSide.entryPoints(om.pkgs), newSide.entryPoints(nm.pkgs)
	for _, name := range sortedEntryNames(newEntries) {
		newFn := newEntries[name]
		oldFn, existed := oldEntries[name]
		isInit := isPackageInit(newFn)
		if !existed && !isInit {
			continue // a new exported function; its own diff entry scores it
		}
		newReach := newSide.reach(newFn)
		oldReach := map[string]string{}
		if existed {
			oldReach = oldSide.reach(oldFn)
		}
		if rc, ok := reachChange(name, oldReach, newReach, isInit); ok {
			md.Reach = append(md.Reach, rc)
			noteRisk(&md, rc.RiskScore)
		}
	}

	md.Unanalyzed = diffInventories(inventory(om), inventory(nm))
	for _, fc := range md.Unanalyzed {
		noteRisk(&md, fc.RiskScore)
	}
	return md
}

// describe summarizes code only the new tree compiles: the packages pkgs
// of module m, which are all of an added module, or the packages the new
// tree newly builds from a module it already used. It reports the
// capability classes their entry points can reach, initializers that reach
// any capability (they run as soon as the package is imported), and the
// high-risk files the analysis cannot see that before, when the old tree
// used the module, did not have.
func (s *depsSide) describe(m *depModule, pkgs []*packages.Package, status string, before *depModule) models.ModuleDiff {
	md := models.ModuleDiff{Path: m.path, Status: status, NewVersion: m.identity}
	classes := make(map[string]struct{})
	entries := s.entryPoints(pkgs)
	for _, name := range sortedEntryNames(entries) {
		fn := entries[name]
		r := s.reach(fn)
		for _, class := range r {
			classes[class] = struct{}{}
		}
		if isPackageInit(fn) {
			if rc, ok := reachChange(name, nil, r, true); ok {
				md.Reach = append(md.Reach, rc)
				noteRisk(&md, rc.RiskScore)
			}
		}
	}
	md.Capabilities = slices.Sorted(maps.Keys(classes))
	var old map[string]string
	if before != nil {
		old = inventory(before)
	}
	for _, fc := range diffInventories(old, inventory(m)) {
		if fc.Kind == "syso" || fc.Kind == "object" || fc.Kind == "linkname" {
			md.Unanalyzed = append(md.Unanalyzed, fc)
			noteRisk(&md, fc.RiskScore)
		}
	}
	return md
}

// newPackages returns the packages of nm that om does not build.
func newPackages(om, nm *depModule) []*packages.Package {
	built := packagesByPath(om)
	var out []*packages.Package
	for _, p := range nm.pkgs {
		if built[p.PkgPath] == nil {
			out = append(out, p)
		}
	}
	return out
}

// noteRisk folds one change's risk into its module's score and count.
func noteRisk(md *models.ModuleDiff, risk int) {
	if risk > md.RiskScore {
		md.RiskScore = risk
	}
	if risk >= models.RiskScoreHigh {
		md.HighRiskChanges++
	}
}

func packagesByPath(m *depModule) map[string]*packages.Package {
	out := make(map[string]*packages.Package, len(m.pkgs))
	for _, p := range m.pkgs {
		out[p.PkgPath] = p
	}
	return out
}

func unionKeys(a, b map[string]*packages.Package) []string {
	keys := make([]string, 0, len(a)+len(b))
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// fingerprintPackage fingerprints every function a package contributes, or
// returns nil for a package this tree does not build.
func (s *depsSide) fingerprintPackage(p *packages.Package) []diff.FingerprintResult {
	if p == nil {
		return nil
	}
	fns := diff.PackageFunctions(s.prog, s.prog.Package(p.Types))
	out := make([]diff.FingerprintResult, 0, len(fns))
	for _, fn := range fns {
		out = append(out, diff.GenerateFingerprint(fn, ir.DefaultLiteralPolicy, false))
	}
	return out
}

// entryPoints returns the API of pkgs: their exported package-level
// functions; the exported methods, promoted ones included, of their
// exported types and of their types an exported alias names; and their
// package initializers. Keys are "import/path.Name", "import/path.(T).M"
// and "import/path.(*T).M".
func (s *depsSide) entryPoints(pkgs []*packages.Package) map[string]*ssa.Function {
	out := make(map[string]*ssa.Function)
	for _, p := range pkgs {
		for _, fn := range diff.PackageFunctions(s.prog, s.prog.Package(p.Types)) {
			if fn.Parent() != nil || fn.Signature.Recv() != nil {
				continue
			}
			if obj, ok := fn.Object().(*types.Func); isPackageInit(fn) || ok && obj.Exported() {
				out[p.PkgPath+"."+SSAFunctionName(fn)] = fn
			}
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || !tn.Exported() {
				continue
			}
			// An alias of another package's type adds no code of this one.
			named, ok := types.Unalias(tn.Type()).(*types.Named)
			if !ok || named.Obj().Pkg() != p.Types {
				continue
			}
			values := s.prog.MethodSets.MethodSet(named)
			pointers := s.prog.MethodSets.MethodSet(types.NewPointer(named))
			for i := 0; i < pointers.Len(); i++ {
				sel, recv := pointers.At(i), "*"+name
				if !sel.Obj().Exported() {
					continue
				}
				if v := values.Lookup(sel.Obj().Pkg(), sel.Obj().Name()); v != nil {
					sel, recv = v, name
				}
				// Interface and generic methods have no single body.
				if fn := s.prog.MethodValue(sel); fn != nil {
					out[p.PkgPath+".("+recv+")."+sel.Obj().Name()] = fn
				}
			}
		}
	}
	return out
}

// isPackageInit reports whether fn is a package initializer.
func isPackageInit(fn *ssa.Function) bool {
	return fn.Name() == "init" && fn.Signature.Recv() == nil && fn.Parent() == nil
}

func sortedEntryNames(m map[string]*ssa.Function) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// reach returns the capability call targets (key -> class) reachable from
// fn through static calls, closures and function values. It descends into
// every function with a body; standard-library functions have none, as
// only third-party packages are built, so the walk stops at them and they
// are classified at the call. Interface and dynamic calls are not followed,
// and neither are calls to other packages' initializers: each package's
// initializer is an entry point of its own, and importing a package that
// was already built runs nothing new.
//
// The answers for every function the walk passes are computed together,
// strongly connected component by component, so the cost over all entry
// points is that of one walk of the graph.
func (s *depsSide) reach(fn *ssa.Function) map[string]string {
	if _, done := s.reached[fn]; !done {
		s.strongConnect(fn)
	}
	return s.reached[fn]
}

// sccState is Tarjan's algorithm's bookkeeping for reach.
type sccState struct {
	index, low map[*ssa.Function]int
	onStack    map[*ssa.Function]bool
	stack      []*ssa.Function
	next       int
}

// followed reports whether the reach walk descends into callee c.
func followed(c *ssa.Function) bool {
	return len(c.Blocks) > 0 && !isPackageInit(c)
}

func (s *depsSide) strongConnect(v *ssa.Function) {
	st := &s.scc
	if st.index == nil {
		st.index, st.low, st.onStack = make(map[*ssa.Function]int), make(map[*ssa.Function]int), make(map[*ssa.Function]bool)
	}
	st.index[v], st.low[v] = st.next, st.next
	st.next++
	st.stack = append(st.stack, v)
	st.onStack[v] = true
	for _, w := range s.calleesOf(v) {
		if !followed(w) {
			continue
		}
		if _, visited := st.index[w]; !visited {
			s.strongConnect(w)
			st.low[v] = min(st.low[v], st.low[w])
		} else if st.onStack[w] {
			st.low[v] = min(st.low[v], st.index[w])
		}
	}
	if st.low[v] != st.index[v] {
		return
	}
	// v roots a component: its members reach what any of them calls
	// directly, and what the components they call reach.
	var members []*ssa.Function
	for {
		w := st.stack[len(st.stack)-1]
		st.stack = st.stack[:len(st.stack)-1]
		st.onStack[w] = false
		members = append(members, w)
		if w == v {
			break
		}
	}
	reached := make(map[string]string)
	for _, m := range members {
		maps.Copy(reached, s.directTargets(m))
		for _, w := range s.calleesOf(m) {
			if followed(w) {
				maps.Copy(reached, s.reached[w])
			}
		}
	}
	for _, m := range members {
		s.reached[m] = reached
	}
}

func (s *depsSide) calleesOf(fn *ssa.Function) []*ssa.Function {
	if cs, ok := s.callees[fn]; ok {
		return cs
	}
	var cs []*ssa.Function
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			for _, op := range instr.Operands(nil) {
				if c, ok := (*op).(*ssa.Function); ok {
					cs = append(cs, c)
				}
			}
		}
	}
	s.callees[fn] = cs
	return cs
}

func (s *depsSide) directTargets(fn *ssa.Function) map[string]string {
	if d, ok := s.direct[fn]; ok {
		return d
	}
	d := make(map[string]string)
	for _, c := range s.calleesOf(fn) {
		// A closure's key never classifies; the walk in reach descends
		// into it instead.
		if key, class, ok := topology.CalleeCapability(c); ok && class != "" {
			d[key] = class
		}
	}
	s.direct[fn] = d
	return d
}

// reachChange reports the capability classes an entry point can reach in
// the new tree but not the old. The first newly reached class is charged
// like a function newly calling it; an initializer adds riskInitReach.
func reachChange(name string, oldReach, newReach map[string]string, isInit bool) (models.ReachChange, bool) {
	oldClasses := make(map[string]bool)
	for _, c := range oldReach {
		oldClasses[c] = true
	}
	added := make(map[string]struct{})
	targets := make(map[string]struct{})
	for key, class := range newReach {
		if !oldClasses[class] {
			added[class] = struct{}{}
			targets[key] = struct{}{}
		}
	}
	if len(added) == 0 {
		return models.ReachChange{}, false
	}
	rc := models.ReachChange{Function: name, Added: slices.Sorted(maps.Keys(added)), Targets: slices.Sorted(maps.Keys(targets))}
	for _, c := range rc.Added {
		rc.RiskScore = max(rc.RiskScore, capabilityRisk[c])
	}
	if isInit {
		rc.RiskScore += riskInitReach
	}
	return rc, true
}

// inventory hashes the files of a module that its build can use but the SSA
// analysis does not cover, keyed by "<kind>:<module-relative path>":
//
//   - in each built package's directory, every source file other than the
//     package's compiled Go files and tests: assembly, C and the other
//     languages cgo compiles, .syso and other object files, and Go files the
//     build configuration excludes (cgo files among them, as the loader
//     disables cgo, which also hides the package's C files from go list);
//   - every file an assembly file #includes, whatever its name or place;
//   - in a module with a cgo file, every other non-Go file anywhere in the
//     module, as #include and #cgo directives reach any file under any name
//     (-l:payload.bin): one that holds machine code is an object, any other
//     file not listed already is "other";
//   - every file a built package embeds.
//
// A symbolic link counts as the regular file it points to.
//
// It also records each //go:linkname directive of the packages' Go files,
// compiled or excluded, as "linkname:<package path>: <directive>".
func inventory(m *depModule) map[string]string {
	out := make(map[string]string)
	rel := func(f string) string {
		if r, err := filepath.Rel(m.dir, f); err == nil {
			return filepath.ToSlash(r)
		}
		return f
	}
	listed := make(map[string]bool)
	hash := func(kind, f string) {
		if sum, ok := hashFile(f); ok {
			out[kind+":"+rel(f)] = sum
			listed[filepath.Clean(f)] = true
		}
	}
	usesCgo := false
	included := make(map[string]bool)
	for _, p := range m.pkgs {
		compiled := make(map[string]bool)
		for _, f := range p.CompiledGoFiles {
			compiled[filepath.Clean(f)] = true
		}
		dirs := make(map[string]struct{})
		for _, f := range append(append(append([]string{}, p.GoFiles...), p.OtherFiles...), p.IgnoredFiles...) {
			dirs[filepath.Dir(f)] = struct{}{}
		}
		for dir := range dirs {
			entries, _ := os.ReadDir(dir) // what could be read
			for _, e := range entries {
				f := filepath.Join(dir, e.Name())
				if compiled[f] || !isRegular(f, e) {
					continue
				}
				kind := fileKind(f)
				switch kind {
				case "cgo":
					usesCgo = true
				case "assembly":
					hashIncludes(f, included, hash)
				}
				if kind != "" {
					hash(kind, f)
				}
			}
		}
		for _, f := range p.EmbedFiles {
			hash("embed", f)
		}
		for _, d := range packageLinknames(p) {
			out["linkname:"+p.PkgPath+": "+d] = d
		}
	}
	if usesCgo {
		filepath.WalkDir(m.dir, func(f string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				switch e.Name() {
				case ".git", ".hg", ".svn", ".bzr":
					return filepath.SkipDir
				}
				return nil
			}
			if strings.EqualFold(filepath.Ext(f), ".go") || listed[f] || !isRegular(f, e) {
				return nil
			}
			kind := fileKind(f)
			if kind == "" {
				kind = "other"
				if isMachineCode(f) {
					kind = "object"
				}
			}
			hash(kind, f)
			return nil
		})
	}
	return out
}

// isRegular reports whether directory entry e, at path f, is a regular file
// or a symbolic link to one. Other files, a FIFO or a device, are never
// read.
func isRegular(f string, e fs.DirEntry) bool {
	if e.Type().IsRegular() {
		return true
	}
	info, err := os.Stat(f) // follows a symbolic link
	return err == nil && info.Mode().IsRegular()
}

// hashFile returns the SHA-256 of a file, read as a stream. Callers pass
// regular files only: opening a FIFO would block.
func hashFile(f string) (string, bool) {
	file, err := os.Open(f)
	if err != nil {
		return "", false
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", false
	}
	return fmt.Sprintf("%x", h.Sum(nil)), true
}

// machineCodeMagic are the leading bytes of ELF and Mach-O (32- and 64-bit,
// both byte orders, and universal) files and of ar archives.
var machineCodeMagic = [][]byte{
	[]byte("\x7fELF"), []byte("!<arch>\n"),
	{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
	{0xca, 0xfe, 0xba, 0xbe},
}

// isMachineCode reports whether a file starts like an object file, a
// library or an executable: an ELF, Mach-O or PE file or an ar archive.
func isMachineCode(f string) bool {
	file, err := os.Open(f)
	if err != nil {
		return false
	}
	defer file.Close()
	buf := make([]byte, 0x40)
	n, _ := io.ReadFull(file, buf)
	head := buf[:n]
	for _, magic := range machineCodeMagic {
		if bytes.HasPrefix(head, magic) {
			return true
		}
	}
	// A PE file starts with a DOS header whose last field locates the
	// "PE\0\0" signature.
	if n < 0x40 || !bytes.HasPrefix(head, []byte("MZ")) {
		return false
	}
	sig := make([]byte, 4)
	_, err = file.ReadAt(sig, int64(binary.LittleEndian.Uint32(head[0x3c:])))
	return err == nil && string(sig) == "PE\x00\x00"
}

// includeDirective matches the quoted #include lines of assembly, which
// the assembler's preprocessor reads like C's: "#include", "# include".
var includeDirective = regexp.MustCompile(`(?m)^[ \t]*#[ \t]*include[ \t]*"([^"\n]+)"`)

// hashIncludes hashes, as assembly, every file an assembly file includes
// with #include "file", directly or through other included files. The
// assembler looks for the file next to the including one first; one found
// only on its search path (textflag.h) is not the module's. Only regular
// files are read.
func hashIncludes(f string, seen map[string]bool, hash func(kind, f string)) {
	data, _ := os.ReadFile(f)
	for _, m := range includeDirective.FindAllSubmatch(data, -1) {
		target := string(m[1])
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(f), target)
		}
		if seen[target] {
			continue
		}
		if info, err := os.Stat(target); err != nil || !info.Mode().IsRegular() {
			continue
		}
		seen[target] = true
		hash("assembly", target)
		hashIncludes(target, seen, hash)
	}
}

// fileKind classifies a file the build can use without the SSA analysis
// seeing it, or returns "" for a compiled-or-irrelevant file: a test, or
// one that is neither source nor object code.
func fileKind(f string) string {
	name := filepath.Base(f)
	switch strings.ToLower(filepath.Ext(name)) {
	case ".go":
		switch {
		case strings.HasSuffix(name, "_test.go"):
			return ""
		case importsC(f):
			return "cgo"
		}
		return "excluded-go"
	case ".s", ".sx":
		return "assembly"
	case ".syso":
		return "syso"
	case ".a", ".o", ".so", ".dylib", ".dll", ".lib":
		return "object"
	case ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m",
		".f", ".for", ".f90", ".swig", ".swigcxx":
		return "c"
	}
	return ""
}

// importsC reports whether a Go file imports "C" (uses cgo).
func importsC(f string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
	if err != nil {
		return false
	}
	for _, imp := range file.Imports {
		if imp.Path.Value == `"C"` {
			return true
		}
	}
	return false
}

// packageLinknames returns the //go:linkname directives of a package's Go
// files: the compiled ones, read from the loaded syntax, and the ones the
// build configuration excludes (cgo files, other platforms' files), which a
// build with cgo or for another platform compiles. Directives are read from
// the parsed comments, so one inside a block comment is not one, and they
// are normalized to single spaces.
func packageLinknames(p *packages.Package) []string {
	files := append([]*ast.File{}, p.Syntax...)
	fset := token.NewFileSet()
	for _, f := range p.IgnoredFiles {
		if !strings.HasSuffix(f, ".go") || strings.HasSuffix(f, "_test.go") {
			continue
		}
		// A file with syntax errors still yields the comments before them.
		if file, _ := parser.ParseFile(fset, f, nil, parser.ParseComments); file != nil {
			files = append(files, file)
		}
	}
	var out []string
	for _, file := range files {
		for _, group := range file.Comments {
			for _, c := range group.List {
				if strings.HasPrefix(c.Text, "//go:linkname ") {
					out = append(out, strings.Join(strings.Fields(c.Text), " "))
				}
			}
		}
	}
	return out
}

// diffInventories reports added, modified and removed unanalyzed files and
// added or removed linkname directives.
func diffInventories(oldInv, newInv map[string]string) []models.FileChange {
	var out []models.FileChange
	keys := make(map[string]struct{})
	for k := range oldInv {
		keys[k] = struct{}{}
	}
	for k := range newInv {
		keys[k] = struct{}{}
	}
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		ov, inOld := oldInv[k]
		nv, inNew := newInv[k]
		change := ""
		switch {
		case !inOld:
			change = "added"
		case !inNew:
			change = "removed"
		case ov != nv:
			change = "modified"
		default:
			continue
		}
		kind, file, _ := strings.Cut(k, ":")
		fc := models.FileChange{File: file, Kind: kind, Change: change}
		if change != "removed" {
			switch kind {
			case "syso", "object":
				fc.RiskScore = riskUnanalyzedSyso
			case "linkname":
				fc.RiskScore = riskUnanalyzedLinkname
			default:
				fc.RiskScore = riskUnanalyzedOther
			}
		}
		out = append(out, fc)
	}
	return out
}
