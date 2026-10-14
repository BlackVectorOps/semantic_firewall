package api

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
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
// changed .syso object links precompiled machine code into the binary, and a
// new //go:linkname directive reaches into another package's internals; both
// are high-risk. Other unanalyzed changes are reported below the threshold.
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
// trees, or when it is replaced by a local directory in both. For each such
// module the diff reports changed functions (paired and scored as in Diff),
// exported functions and package initializers that newly reach a capability
// class, and changes to files the analysis cannot see. Modules only in the
// new tree are reported with the capability classes their exported
// functions and initializers can reach.
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
	paths := make(map[string]bool)
	for p := range oldSide.modules {
		paths[p] = true
	}
	for p := range newSide.modules {
		paths[p] = true
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	for _, path := range sorted {
		om, nm := oldSide.modules[path], newSide.modules[path]
		var md models.ModuleDiff
		switch {
		case om == nil:
			md = newSide.describeAdded(nm)
			out.Summary.ModulesAdded++
		case nm == nil:
			md = models.ModuleDiff{Path: path, Status: models.ModuleRemoved, OldVersion: om.version}
			out.Summary.ModulesRemoved++
		case om.identity == nm.identity && !om.localReplace:
			continue
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

// depsSide is one tree's build: the SSA of its whole import graph, with the
// third-party packages built, grouped by module.
type depsSide struct {
	prog    *ssa.Program
	modules map[string]*depModule

	// callees and direct cache, per function, the functions it references
	// and the capability call targets it references directly.
	callees map[*ssa.Function][]*ssa.Function
	direct  map[*ssa.Function]map[string]string
}

type depModule struct {
	path, version string
	// identity is the version, or the replacement, the build uses.
	identity     string
	localReplace bool
	dir          string
	pkgs         []*packages.Package
}

func loadDepsSide(dir string) (*depsSide, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
			packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo |
			packages.NeedModule | packages.NeedEmbedFiles,
		Dir:  dir,
		Env:  diff.GetHardenedEnv(),
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
	}
	var thirdParty []*packages.Package
	packages.Visit(roots, nil, func(p *packages.Package) {
		if p.Module == nil || own[p.Module.Path] {
			return
		}
		thirdParty = append(thirdParty, p)
		m := side.modules[p.Module.Path]
		if m == nil {
			m = &depModule{path: p.Module.Path, version: p.Module.Version, identity: p.Module.Version, dir: p.Module.Dir}
			if r := p.Module.Replace; r != nil {
				if r.Version != "" {
					m.identity = r.Path + "@" + r.Version
				} else {
					m.identity, m.localReplace = "replace "+r.Path, true
				}
				if r.Dir != "" {
					m.dir = r.Dir
				}
			}
			side.modules[p.Module.Path] = m
		}
		m.pkgs = append(m.pkgs, p)
	})
	for _, m := range side.modules {
		sort.Slice(m.pkgs, func(i, j int) bool { return m.pkgs[i].PkgPath < m.pkgs[j].PkgPath })
	}

	var buildErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				buildErr = fmt.Errorf("SSA construction for %s panicked: %v", dir, r)
			}
		}()
		side.prog, _ = ssautil.AllPackages(roots, ssa.InstantiateGenerics)
		for _, p := range thirdParty {
			if sp := side.prog.Package(p.Types); sp != nil {
				sp.Build()
			}
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

	oldEntries, newEntries := oldSide.entryPoints(om), newSide.entryPoints(nm)
	for _, name := range sortedEntryNames(newEntries) {
		newFn := newEntries[name]
		oldFn, existed := oldEntries[name]
		isInit := newFn.Name() == "init" && newFn.Signature.Recv() == nil
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

// describeAdded summarizes a module only the new tree compiles: the
// capability classes its entry points reach, and initializers that reach
// any capability, which run as soon as the module is imported.
func (s *depsSide) describeAdded(m *depModule) models.ModuleDiff {
	md := models.ModuleDiff{Path: m.path, Status: models.ModuleAdded, NewVersion: m.identity}
	classes := make(map[string]bool)
	entries := s.entryPoints(m)
	for _, name := range sortedEntryNames(entries) {
		fn := entries[name]
		r := s.reach(fn)
		for _, class := range r {
			classes[class] = true
		}
		if fn.Name() == "init" && fn.Signature.Recv() == nil {
			if rc, ok := reachChange(name, nil, r, true); ok {
				md.Reach = append(md.Reach, rc)
				noteRisk(&md, rc.RiskScore)
			}
		}
	}
	for c := range classes {
		md.Capabilities = append(md.Capabilities, c)
	}
	sort.Strings(md.Capabilities)
	for _, fc := range diffInventories(nil, inventory(m)) {
		if fc.Kind == "syso" || fc.Kind == "linkname" {
			md.Unanalyzed = append(md.Unanalyzed, fc)
			noteRisk(&md, fc.RiskScore)
		}
	}
	return md
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
	sp := s.prog.Package(p.Types)
	if sp == nil {
		return nil
	}
	fns := diff.PackageFunctions(s.prog, sp)
	out := make([]diff.FingerprintResult, 0, len(fns))
	for _, fn := range fns {
		out = append(out, diff.GenerateFingerprint(fn, ir.DefaultLiteralPolicy, false))
	}
	return out
}

// entryPoints returns a module's exported package-level functions, the
// exported methods of its exported types, and its package initializers,
// keyed by "import/path.Name" or "import/path.(*T).M".
func (s *depsSide) entryPoints(m *depModule) map[string]*ssa.Function {
	out := make(map[string]*ssa.Function)
	for _, p := range m.pkgs {
		sp := s.prog.Package(p.Types)
		if sp == nil {
			continue
		}
		for _, fn := range diff.PackageFunctions(s.prog, sp) {
			if fn.Parent() != nil {
				continue
			}
			isInit := fn.Name() == "init" && fn.Signature.Recv() == nil
			if !isInit && !isExportedAPI(fn) {
				continue
			}
			out[p.PkgPath+"."+SSAFunctionName(fn)] = fn
		}
	}
	return out
}

// isExportedAPI reports whether fn is an exported package-level function or
// an exported method of an exported named type.
func isExportedAPI(fn *ssa.Function) bool {
	obj, ok := fn.Object().(*types.Func)
	if !ok || !obj.Exported() {
		return false
	}
	recv := fn.Signature.Recv()
	if recv == nil {
		return true
	}
	t := recv.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Exported()
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
// are classified at the call. Interface and dynamic calls are not followed.
func (s *depsSide) reach(fn *ssa.Function) map[string]string {
	out := make(map[string]string)
	seen := map[*ssa.Function]bool{fn: true}
	queue := []*ssa.Function{fn}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		for key, class := range s.directTargets(f) {
			out[key] = class
		}
		for _, c := range s.calleesOf(f) {
			if !seen[c] && len(c.Blocks) > 0 {
				seen[c] = true
				queue = append(queue, c)
			}
		}
	}
	return out
}

func (s *depsSide) calleesOf(fn *ssa.Function) []*ssa.Function {
	if cs, ok := s.callees[fn]; ok {
		return cs
	}
	var cs []*ssa.Function
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			for _, op := range instr.Operands(nil) {
				if op != nil && *op != nil {
					if c, ok := (*op).(*ssa.Function); ok {
						cs = append(cs, c)
					}
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
		if c.Parent() != nil {
			continue
		}
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
	added := make(map[string]bool)
	var targets []string
	for key, class := range newReach {
		if !oldClasses[class] {
			added[class] = true
			targets = append(targets, key)
		}
	}
	if len(added) == 0 {
		return models.ReachChange{}, false
	}
	rc := models.ReachChange{Function: name, Targets: targets}
	for c := range added {
		rc.Added = append(rc.Added, c)
		if r := capabilityRisk[c]; r > rc.RiskScore {
			rc.RiskScore = r
		}
	}
	if isInit {
		rc.RiskScore += riskInitReach
	}
	sort.Strings(rc.Added)
	sort.Strings(rc.Targets)
	return rc, true
}

// inventory hashes the files of a module's built packages that the SSA
// analysis does not cover, keyed by "<kind>:<module-relative path>", and
// records each //go:linkname directive in the compiled Go files as
// "linkname:<path>: <directive>".
func inventory(m *depModule) map[string]string {
	out := make(map[string]string)
	rel := func(f string) string {
		if r, err := filepath.Rel(m.dir, f); err == nil {
			return filepath.ToSlash(r)
		}
		return f
	}
	hash := func(kind, f string) {
		data, err := os.ReadFile(f)
		if err != nil {
			return
		}
		sum := sha256.Sum256(data)
		out[kind+":"+rel(f)] = fmt.Sprintf("%x", sum[:])
	}
	for _, p := range m.pkgs {
		for _, f := range p.OtherFiles {
			hash(otherFileKind(f), f)
		}
		for _, f := range p.IgnoredFiles {
			if strings.HasSuffix(f, ".go") {
				kind := "excluded-go"
				if importsC(f) {
					kind = "cgo"
				}
				hash(kind, f)
			}
		}
		for _, f := range p.EmbedFiles {
			hash("embed", f)
		}
		for _, f := range p.CompiledGoFiles {
			for _, d := range linknames(f) {
				out["linkname:"+rel(f)+": "+d] = d
			}
		}
	}
	return out
}

func otherFileKind(f string) string {
	switch strings.ToLower(filepath.Ext(f)) {
	case ".s":
		return "assembly"
	case ".syso":
		return "syso"
	case ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m":
		return "c"
	default:
		return "other"
	}
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

// linknames returns the //go:linkname directives of a Go file.
func linknames(f string) []string {
	data, err := os.ReadFile(f)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); strings.HasPrefix(line, "//go:linkname ") {
			out = append(out, strings.Join(strings.Fields(line), " "))
		}
	}
	return out
}

// diffInventories reports added, modified and removed unanalyzed files and
// added or removed linkname directives.
func diffInventories(oldInv, newInv map[string]string) []models.FileChange {
	var out []models.FileChange
	keys := make(map[string]bool)
	for k := range oldInv {
		keys[k] = true
	}
	for k := range newInv {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
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
			case "syso":
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
