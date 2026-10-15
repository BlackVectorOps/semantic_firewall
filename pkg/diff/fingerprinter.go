package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type FingerprintResult struct {
	FunctionName string
	Fingerprint  string
	CanonicalIR  string
	Pos          token.Pos
	Line         int
	Filename     string
	fn           *ssa.Function
}

func (r FingerprintResult) GetSSAFunction() *ssa.Function {
	return r.fn
}

type virtualControlFlowState struct {
	swappedBlocks map[*ssa.BasicBlock]bool
	virtualBinOps map[*ssa.BinOp]token.Token
}

func newVirtualControlFlowState() *virtualControlFlowState {
	return &virtualControlFlowState{
		swappedBlocks: make(map[*ssa.BasicBlock]bool),
		virtualBinOps: make(map[*ssa.BinOp]token.Token),
	}
}

func computeVirtualControlFlow(fn *ssa.Function) *virtualControlFlowState {
	state := newVirtualControlFlowState()

	for _, block := range fn.Blocks {
		if len(block.Instrs) == 0 {
			continue
		}
		if ifInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If); ok {
			if binOp, ok := ifInstr.Cond.(*ssa.BinOp); ok {
				isSafeToSwap := func(t types.Type) bool {
					if basic, ok := t.Underlying().(*types.Basic); ok {
						return (basic.Info() & (types.IsInteger | types.IsString)) != 0
					}
					return false
				}

				if !isSafeToSwap(binOp.X.Type()) || !isSafeToSwap(binOp.Y.Type()) {
					continue
				}

				// FIX: Re-enabled Referrers check.
				// We can only swap the operator (e.g. GEQ -> LSS) if we compensate by swapping the branches
				// of the If instruction. If the BinOp result is used by ANY other instruction (e.g. Return, Store, or another If),
				// the value they receive would be inverted, causing logic corruption.
				// We filter out DebugRef, as it doesn't impact program semantics.
				if refs := binOp.Referrers(); refs != nil {
					isSafe := true
					for _, ref := range *refs {
						if _, ok := ref.(*ssa.DebugRef); ok {
							continue
						}
						// If the user is not THIS specific If instruction, it is unsafe to swap.
						if ref != ifInstr {
							isSafe = false
							break
						}
					}
					if !isSafe {
						continue
					}
				}

				var newOp token.Token
				swap := false
				switch binOp.Op {
				case token.GEQ:
					newOp = token.LSS
					swap = true
				case token.GTR:
					newOp = token.LEQ
					swap = true
				}

				if swap {
					if len(block.Succs) != 2 {
						continue
					}
					state.virtualBinOps[binOp] = newOp
					state.swappedBlocks[block] = true
				}
			}
		}
	}
	return state
}

const MaxFunctionBlocks = 5000

// rangeFuncYield is the Synthetic tag x/tools gives the closure holding the
// body of a range-over-func loop. Unlike other synthetic functions, it is
// user code.
const rangeFuncYield = "range-over-func yield"

// oversizedFingerprint hashes the raw SSA of a function too large to
// canonicalize. It is deterministic but not canonical: a rename can change it.
// A constant placeholder would instead make every change to such a function
// invisible -- padding a function past MaxFunctionBlocks would hide anything.
func oversizedFingerprint(fn *ssa.Function) string {
	h := sha256.New()
	fmt.Fprintf(h, "oversized\n%s\n", fn.Signature)
	for _, b := range fn.Blocks {
		fmt.Fprintf(h, "b%d:\n", b.Index)
		for _, instr := range b.Instrs {
			if v, ok := instr.(ssa.Value); ok && v.Name() != "" {
				fmt.Fprintf(h, "%s = ", v.Name())
			}
			fmt.Fprintf(h, "%s\n", instr)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// functionPosition returns the file and line of fn's position, as
// FingerprintResult reports them: where fn is written, whatever a //line
// directive says. A diff keeps a file's functions by this file, and a
// directive must not move a function out of the file it is in, nor into
// another.
func functionPosition(fn *ssa.Function) (filename string, line int) {
	if fn.Prog == nil || fn.Prog.Fset == nil {
		return "", 0
	}
	p := fn.Prog.Fset.PositionFor(fn.Pos(), false)
	return p.Filename, p.Line
}

func GenerateFingerprint(fn *ssa.Function, policy ir.LiteralPolicy, strictMode bool) FingerprintResult {
	filename, line := functionPosition(fn)

	if len(fn.Blocks) > MaxFunctionBlocks {
		return FingerprintResult{
			FunctionName: fn.RelString(nil),
			Fingerprint:  oversizedFingerprint(fn),
			CanonicalIR:  fmt.Sprintf("; Not canonicalized: function too large (%d blocks > %d); fingerprint is over raw SSA", len(fn.Blocks), MaxFunctionBlocks),
			Pos:          fn.Pos(),
			Line:         line,
			Filename:     filename,
			fn:           fn,
		}
	}

	virtualCF := computeVirtualControlFlow(fn)
	canonicalizer := ir.AcquireCanonicalizer(policy)
	defer ir.ReleaseCanonicalizer(canonicalizer)

	canonicalizer.StrictMode = strictMode
	canonicalizer.ApplyVirtualControlFlowFromState(virtualCF.swappedBlocks, virtualCF.virtualBinOps)
	canonicalIR := canonicalizer.CanonicalizeFunction(fn)

	hash := sha256.Sum256([]byte(canonicalIR))
	fingerprint := hex.EncodeToString(hash[:])

	return FingerprintResult{
		FunctionName: fn.RelString(nil),
		Fingerprint:  fingerprint,
		CanonicalIR:  canonicalIR,
		Pos:          fn.Pos(),
		Line:         line,
		Filename:     filename,
		fn:           fn,
	}
}

func FingerprintSource(filename string, src string, policy ir.LiteralPolicy) ([]FingerprintResult, error) {
	return FingerprintSourceAdvanced(filename, src, policy, false)
}

func FingerprintSourceAdvanced(filename string, src string, policy ir.LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	return FingerprintSourceWhere(filename, src, policy, strictMode, nil)
}

// FingerprintSourceWhere is FingerprintSourceAdvanced restricted as
// FingerprintPackagesWhere restricts FingerprintPackages.
func FingerprintSourceWhere(filename string, src string, policy ir.LiteralPolicy, strictMode bool, keep func(filename string) bool) ([]FingerprintResult, error) {
	initialPkgs, err := loadPackagesFromSource(filename, src)
	if err != nil {
		return nil, err
	}

	return FingerprintPackagesWhere(initialPkgs, policy, strictMode, keep)
}

// WorkspaceFile returns the go.work file that governs builds in dir as the
// go command finds it, the first in dir or a parent, or "" when there is
// none. The search stops at the repository's root, the first directory
// holding a .git entry: a tree checked out inside another must not take
// the outer tree's workspace.
func WorkspaceFile(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.work")); err == nil && !info.IsDir() {
			return filepath.Join(dir, "go.work")
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// HardenedEnvFor is GetHardenedEnv for loading packages in dir: it uses the
// workspace that governs dir (see WorkspaceFile), as the go command builds
// it, and none when there is none.
func HardenedEnvFor(dir string) []string {
	return withWorkspace(GetHardenedEnv(), dir)
}

// withWorkspace sets env's GOWORK to the workspace that governs dir.
func withWorkspace(env []string, dir string) []string {
	if work := WorkspaceFile(dir); work != "" {
		return append(env, "GOWORK="+work) // the last value of a variable wins
	}
	return env
}

// GetHardenedEnv returns the environment for loading untrusted source: no
// cgo, no network (GOPROXY=off), a read-only module graph, no workspace
// (see HardenedEnvFor) and the local toolchain.
func GetHardenedEnv() []string {
	// FIX: Ensure return is OUTSIDE the loop so we don't truncate the environment.
	env := make([]string, 0, len(os.Environ())+7)
	for _, e := range os.Environ() {
		upperE := strings.ToUpper(e)
		switch {
		case strings.HasPrefix(upperE, "CGO_ENABLED="),
			strings.HasPrefix(upperE, "GOPROXY="),
			strings.HasPrefix(upperE, "GOFLAGS="),
			strings.HasPrefix(upperE, "GONOSUMDB="),
			strings.HasPrefix(upperE, "GOWORK="),
			strings.HasPrefix(upperE, "GO111MODULE="),
			strings.HasPrefix(upperE, "GOTOOLCHAIN="):
			continue
		}
		env = append(env, e)
	}
	env = append(env, "CGO_ENABLED=0", "GOPROXY=off", "GOFLAGS=-mod=readonly", "GONOSUMDB=*", "GOWORK=off", "GO111MODULE=on", "GOTOOLCHAIN=local")
	return env
}

// hardenedEnvWithProxy is GetHardenedEnv with the GOPROXY value overridden.
// All other hardening (CGO_ENABLED=0, GOFLAGS=-mod=readonly, etc.) is preserved.
func hardenedEnvWithProxy(proxy string) []string {
	env := make([]string, 0, len(os.Environ())+7)
	for _, e := range os.Environ() {
		upperE := strings.ToUpper(e)
		switch {
		case strings.HasPrefix(upperE, "CGO_ENABLED="),
			strings.HasPrefix(upperE, "GOPROXY="),
			strings.HasPrefix(upperE, "GOFLAGS="),
			strings.HasPrefix(upperE, "GONOSUMDB="),
			strings.HasPrefix(upperE, "GOWORK="),
			strings.HasPrefix(upperE, "GO111MODULE="),
			strings.HasPrefix(upperE, "GOTOOLCHAIN="):
			continue
		}
		env = append(env, e)
	}
	env = append(env, "CGO_ENABLED=0", "GOPROXY="+proxy, "GOFLAGS=-mod=readonly", "GONOSUMDB=*", "GOWORK=off", "GO111MODULE=on", "GOTOOLCHAIN=local")
	return env
}

func loadPackagesFromSource(filename string, src string) ([]*packages.Package, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("input source code is empty")
	}

	sourceDir := filepath.Dir(filename)
	absFilename, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path for %s: %w", filename, err)
	}

	cfg := sourceLoaderConfig(sourceDir, map[string][]byte{absFilename: []byte(src)})

	initialPkgs, err := loadSource(cfg, "file="+absFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to execute loader: %w", err)
	}

	// A file the default build leaves out (a _test.go file, a GOOS/GOARCH
	// name suffix, or a //go:build line that does not hold for this host) is
	// in none of the loaded packages. Reload under a configuration that
	// includes it.
	if !packagesContain(initialPkgs, absFilename) && strings.HasSuffix(absFilename, "_test.go") {
		cfg.Tests = true
		if initialPkgs, err = loadSource(cfg, "file="+absFilename); err != nil {
			return nil, fmt.Errorf("failed to execute loader: %w", err)
		}
	}
	if !packagesContain(initialPkgs, absFilename) {
		goos, goarch, tags, ok := buildConfigFor(absFilename, src)
		if !ok {
			return nil, fmt.Errorf("%s is excluded by its build constraints for every known GOOS/GOARCH and tag combination", filename)
		}
		cfg.Env = append(HardenedEnvFor(sourceDir), "GOOS="+goos, "GOARCH="+goarch)
		if len(tags) > 0 {
			cfg.BuildFlags = []string{"-tags=" + strings.Join(tags, ",")}
		}
		if initialPkgs, err = loadSource(cfg, "file="+absFilename); err != nil {
			return nil, fmt.Errorf("failed to execute loader: %w", err)
		}
	}
	if cfg.Tests {
		// Keep only the test variant that compiles this file, not the
		// package itself or the synthesized test main.
		var withFile []*packages.Package
		for _, p := range initialPkgs {
			if packagesContain([]*packages.Package{p}, absFilename) {
				withFile = append(withFile, p)
			}
		}
		initialPkgs = withFile
	}

	var errorMessages strings.Builder
	packages.Visit(initialPkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			errorMessages.WriteString(e.Error() + "\n")
		}
	})

	if len(initialPkgs) == 0 && errorMessages.Len() > 0 {
		return nil, fmt.Errorf("packages contain errors and no packages were loaded: \n%s", errorMessages.String())
	}

	return initialPkgs, nil
}

// sourceLoaderConfig is the go/packages configuration every source load
// uses: full syntax and types for the whole import graph, the hardened
// environment (CGO_ENABLED=0, GOPROXY=off, GOFLAGS=-mod=readonly,
// GOTOOLCHAIN=local) with the workspace that governs dir, no test
// variants, and the given file contents as overlays.
func sourceLoaderConfig(dir string, overlay map[string][]byte) *packages.Config {
	return &packages.Config{
		Dir:     dir,
		Mode:    packages.LoadAllSyntax,
		Fset:    token.NewFileSet(),
		Overlay: overlay,
		Tests:   false,
		Env:     HardenedEnvFor(dir),
	}
}

// LoadFiles loads, with one go/packages call run from dir, the packages
// that compile the given files: absolute paths mapped to their contents,
// which are used as overlays. It uses the same configuration as the
// single-file loader behind FingerprintSource, so a package loads the same
// way either way. Unlike FingerprintSource it does not retry a file the
// default build leaves out (a _test.go file, a GOOS suffix, a //go:build
// line): such a file is in none of the returned packages, and
// PackagesContain reports it.
func LoadFiles(dir string, files map[string][]byte) ([]*packages.Package, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no files to load")
	}
	patterns := make([]string, 0, len(files))
	for f := range files {
		patterns = append(patterns, "file="+f)
	}
	sort.Strings(patterns)
	pkgs, err := loadSource(sourceLoaderConfig(dir, files), patterns...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute loader: %w", err)
	}
	return pkgs, nil
}

// PackagesContain reports whether any of pkgs compiles the file at absPath.
func PackagesContain(pkgs []*packages.Package, absPath string) bool {
	return packagesContain(pkgs, filepath.Clean(absPath))
}

// packagesContain reports whether any of pkgs compiles the file at absPath.
func packagesContain(pkgs []*packages.Package, absPath string) bool {
	for _, p := range pkgs {
		for _, files := range [][]string{p.GoFiles, p.CompiledGoFiles} {
			for _, f := range files {
				if filepath.Clean(f) == absPath {
					return true
				}
			}
		}
	}
	return false
}

// knownPlatforms are GOOS/GOARCH pairs tried, after the host's own, when a
// file's build constraints exclude it from the host build. All are valid
// `go tool dist list` targets.
var knownPlatforms = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"}, {"linux", "386"}, {"linux", "arm"},
	{"linux", "ppc64le"}, {"linux", "s390x"}, {"linux", "riscv64"}, {"linux", "loong64"},
	{"linux", "mips64le"}, {"darwin", "arm64"}, {"darwin", "amd64"},
	{"windows", "amd64"}, {"windows", "arm64"}, {"windows", "386"},
	{"freebsd", "amd64"}, {"freebsd", "arm64"}, {"netbsd", "amd64"}, {"openbsd", "amd64"},
	{"dragonfly", "amd64"}, {"solaris", "amd64"}, {"illumos", "amd64"}, {"aix", "ppc64"},
	{"android", "arm64"}, {"ios", "arm64"}, {"js", "wasm"}, {"wasip1", "wasm"}, {"plan9", "amd64"},
}

// maxCustomTags bounds the tag subsets buildConfigFor tries (2^n).
const maxCustomTags = 4

// buildConfigFor finds a GOOS, GOARCH and set of custom build tags under
// which the file's name suffix and //go:build line include it, using
// go/build's own constraint matching on src. Cgo is assumed disabled, as
// the loader runs with CGO_ENABLED=0.
func buildConfigFor(absFilename, src string) (goos, goarch string, tags []string, ok bool) {
	ctxt := build.Default
	ctxt.CgoEnabled = false
	ctxt.OpenFile = func(path string) (io.ReadCloser, error) {
		if filepath.Clean(path) == absFilename {
			return io.NopCloser(strings.NewReader(src)), nil
		}
		return os.Open(path)
	}
	custom := customBuildTags(src)
	if len(custom) > maxCustomTags {
		custom = custom[:maxCustomTags]
	}
	platforms := append([][2]string{{build.Default.GOOS, build.Default.GOARCH}}, knownPlatforms...)
	dir, name := filepath.Dir(absFilename), filepath.Base(absFilename)
	for _, p := range platforms {
		for mask := 0; mask < 1<<len(custom); mask++ {
			var set []string
			for i, t := range custom {
				if mask&(1<<i) != 0 {
					set = append(set, t)
				}
			}
			ctxt.GOOS, ctxt.GOARCH, ctxt.BuildTags = p[0], p[1], set
			if match, err := ctxt.MatchFile(dir, name); err == nil && match {
				return p[0], p[1], set, true
			}
		}
	}
	return "", "", nil, false
}

// customBuildTags returns, sorted, the tags in src's //go:build lines that
// are not platform, toolchain or release tags and so must be supplied with
// -tags.
func customBuildTags(src string) []string {
	platform := map[string]bool{"unix": true, "cgo": true, "gc": true, "gccgo": true}
	for _, p := range knownPlatforms {
		platform[p[0]], platform[p[1]] = true, true
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			continue
		}
		var walk func(constraint.Expr)
		walk = func(e constraint.Expr) {
			switch e := e.(type) {
			case *constraint.TagExpr:
				if !platform[e.Tag] && !strings.HasPrefix(e.Tag, "go1.") && !strings.HasPrefix(e.Tag, "goexperiment.") {
					seen[e.Tag] = true
				}
			case *constraint.NotExpr:
				walk(e.X)
			case *constraint.AndExpr:
				walk(e.X)
				walk(e.Y)
			case *constraint.OrExpr:
				walk(e.X)
				walk(e.Y)
			}
		}
		walk(expr)
	}
	tags := make([]string, 0, len(seen))
	for t := range seen {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

func FingerprintPackages(initialPkgs []*packages.Package, policy ir.LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	return FingerprintPackagesWhere(initialPkgs, policy, strictMode, nil)
}

// FingerprintPackagesWhere is FingerprintPackages for the functions whose
// file, as FingerprintResult.Filename names it, keep accepts, and those
// without a file; a nil keep accepts every file. The other functions are
// not canonicalized: a diff of a few files of a large package reads only
// their functions.
func FingerprintPackagesWhere(initialPkgs []*packages.Package, policy ir.LiteralPolicy, strictMode bool, keep func(filename string) bool) ([]FingerprintResult, error) {
	if len(initialPkgs) == 0 {
		return nil, fmt.Errorf("input packages list is empty")
	}

	prog, _, err := ir.BuildSSAFromPackages(initialPkgs)
	if err != nil {
		return nil, fmt.Errorf("failed to build SSA: %w", err)
	}

	var results []FingerprintResult
	visited := make(map[*ssa.Function]bool)
	accept := func(fn *ssa.Function) bool {
		file, _ := functionPosition(fn)
		return keep == nil || file == "" || keep(file)
	}

	for _, pkg := range initialPkgs {
		if pkg.Types == nil {
			continue
		}

		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}

		for _, member := range ssaPkg.Members {
			switch mem := member.(type) {
			case *ssa.Function:
				processFunctionAndAnons(mem, policy, strictMode, &results, visited, accept)
			case *ssa.Type:
				if named, ok := mem.Type().(*types.Named); ok {
					for i := 0; i < named.NumMethods(); i++ {
						m := named.Method(i)
						if fn := prog.FuncValue(m); fn != nil {
							processFunctionAndAnons(fn, policy, strictMode, &results, visited, accept)
						}
					}
				}
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].FunctionName < results[j].FunctionName
	})

	return results, nil
}

// processFunctionAndAnons fingerprints fn, when accept accepts it, and its
// anonymous functions, which accept judges on their own: a //line
// directive can place a closure in another file than its parent.
func processFunctionAndAnons(fn *ssa.Function, policy ir.LiteralPolicy, strictMode bool, results *[]FingerprintResult, visited map[*ssa.Function]bool, accept func(*ssa.Function) bool) {
	if visited[fn] {
		return
	}
	visited[fn] = true

	if fn.Synthetic != "" && fn.Name() != "init" && fn.Synthetic != rangeFuncYield {
		return
	}

	if len(fn.Blocks) > 0 && accept(fn) {
		result := GenerateFingerprint(fn, policy, strictMode)
		*results = append(*results, result)
	}

	for _, anon := range fn.AnonFuncs {
		processFunctionAndAnons(anon, policy, strictMode, results, visited, accept)
	}
}

// LoadMeta records what the tree loader did for a particular FingerprintTree
// invocation. Carried alongside results so callers can tag analysis output
// with whether a real go.mod was found or whether one was synthesized.
type LoadMeta struct {
	HadGoMod         bool     // real go.mod found at or above rootDir
	SynthesizedGoMod bool     // loader supplied a synthetic go.mod via overlay
	ModulePath       string   // module path used for resolution (real or synthetic)
	LoadErrors       []string // per-package errors encountered during Load
}

// TreeLoadOptions customises the tree-mode loader. The zero value is safe and
// matches the behaviour of FingerprintTree/FingerprintTreeAdvanced (secure
// hardened defaults: GOPROXY=off, synthetic module path for no-go.mod trees).
type TreeLoadOptions struct {
	// Proxy overrides the GOPROXY setting passed to the Go toolchain during
	// tree loading. If empty, the hardened default ("off") is used, which
	// prevents any external network access. Set to a proxy URL (e.g.
	// "https://proxy.golang.org,direct") when analysing source trees whose
	// declared dependencies are not yet cached in GOMODCACHE. All other
	// hardening applied by GetHardenedEnv (CGO_ENABLED=0, GOFLAGS, etc.)
	// remains in effect regardless of this field.
	Proxy string

	// ModuleNameHint is used as the module path in the synthesised go.mod
	// when a source tree has no real go.mod. If empty, the stable default
	// "synthetic.local/anonymous" is used. Setting this to the tree's actual
	// module path (e.g. "github.com/spf13/cobra") resolves same-module
	// sub-package imports correctly in pre-modules-era multi-package trees.
	ModuleNameHint string
}

// FingerprintTree fingerprints Go source under rootDir using a tree-mode load.
// If a real go.mod is found at or above rootDir, it's used directly. Otherwise
// a synthetic go.mod is supplied via packages.Config.Overlay (no disk write)
// so the loader has a canonical module path to resolve through — this fixes
// the qualifier-corruption case where types.Type.String() would otherwise
// carry a temp-dir-synthesized path.
//
// fileFilter, if non-nil, keeps only function fingerprints whose source file
// satisfies the predicate. Use it to avoid fingerprinting the whole tree when
// the caller only cares about a subset (e.g., changed files in a diff).
//
// GOPROXY=off is preserved via GetHardenedEnv(); files that import external
// modules without resolvable deps will still parse-fail by design.
//
// KNOWN LIMITATION — same-module sub-package imports in real multi-package
// trees: when no real go.mod is found, the synthetic go.mod declares module
// "synthetic.local/anonymous" (see syntheticModulePath). For self-contained
// single-package trees (the synthetic-corpus shape this code was first
// validated against) this is fine — no imports need to resolve through the
// module path. For real multi-package modules whose internal files import
// other sub-packages of the same module (e.g., github.com/google/go-cmp's
// cmp/compare.go importing github.com/google/go-cmp/cmp/internal/diff),
// the synthetic module identity does NOT match the import paths declared in
// source, so the sub-package lookup fails with
// "cannot find module providing package <real-module-path>/<subpath>" even
// though the sub-package's source is present on disk in the tree.
//
// Verified by real-corpus triage of the 3 genuine same-package-sibling
// commits in the pilot (go-cmp 8ebdfab3, x/text c8872a1a, x/text db455d00):
// in each case the failing sub-package directory EXISTS at the worktree-
// root-relative path that the real import declares, so a synthesized go.mod
// declaring the REAL module name resolves the imports correctly. Pass that
// name as TreeLoadOptions.ModuleNameHint via FingerprintTreeWithOptions.
// Affected corpus: pre-modules-era multi-package trees (modern commits carry
// their own go.mod and don't go through this synthesis path).
func FingerprintTree(rootDir string, fileFilter func(string) bool, policy ir.LiteralPolicy) ([]FingerprintResult, LoadMeta, error) {
	return fingerprintTreeInternal(rootDir, fileFilter, policy, false, TreeLoadOptions{})
}

// FingerprintTreeAdvanced is the strict-mode variant of FingerprintTree.
func FingerprintTreeAdvanced(rootDir string, fileFilter func(string) bool, policy ir.LiteralPolicy, strictMode bool) ([]FingerprintResult, LoadMeta, error) {
	return fingerprintTreeInternal(rootDir, fileFilter, policy, strictMode, TreeLoadOptions{})
}

// FingerprintTreeWithOptions is the options-driven variant of FingerprintTree.
// Use this to configure GOPROXY (e.g. to allow downloading missing dependencies)
// or to supply a module name hint for pre-modules-era source trees that have no
// go.mod. The zero TreeLoadOptions value is identical to calling FingerprintTree.
func FingerprintTreeWithOptions(rootDir string, fileFilter func(string) bool, policy ir.LiteralPolicy, opts TreeLoadOptions) ([]FingerprintResult, LoadMeta, error) {
	return fingerprintTreeInternal(rootDir, fileFilter, policy, false, opts)
}

func fingerprintTreeInternal(rootDir string, fileFilter func(string) bool, policy ir.LiteralPolicy, strictMode bool, opts TreeLoadOptions) ([]FingerprintResult, LoadMeta, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, LoadMeta{}, fmt.Errorf("resolve absolute path for %s: %w", rootDir, err)
	}

	pkgs, meta, err := loadPackagesFromTree(absRoot, opts)
	if err != nil {
		return nil, meta, err
	}
	if len(pkgs) == 0 {
		return nil, meta, fmt.Errorf("no packages loaded under %s", absRoot)
	}

	results, err := FingerprintPackages(pkgs, policy, strictMode)
	if err != nil {
		return nil, meta, err
	}

	if fileFilter != nil {
		filtered := results[:0]
		for _, r := range results {
			if fileFilter(r.Filename) {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	return results, meta, nil
}

func loadPackagesFromTree(rootDir string, opts TreeLoadOptions) ([]*packages.Package, LoadMeta, error) {
	var meta LoadMeta

	proxy := opts.Proxy
	if proxy == "" {
		proxy = "off"
	}

	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,
		Env:  hardenedEnvWithProxy(proxy),
	}

	modDir, modPath := findGoMod(rootDir)
	if modDir != "" {
		meta.HadGoMod = true
		meta.ModulePath = modPath
		cfg.Dir = modDir
		cfg.Env = withWorkspace(cfg.Env, modDir)
	} else {
		// Synthesize a go.mod via overlay so the loader has a canonical
		// module path. Fixes the qualifier-corruption case where the loader
		// would otherwise synthesize a path from the temp directory.
		meta.HadGoMod = false
		meta.SynthesizedGoMod = true
		modName := opts.ModuleNameHint
		if modName == "" {
			modName = syntheticModulePath()
		}
		meta.ModulePath = modName
		cfg.Dir = rootDir
		cfg.Overlay = map[string][]byte{
			filepath.Join(rootDir, "go.mod"): []byte(fmt.Sprintf("module %s\n\ngo 1.21\n", modName)),
		}
	}

	// Load the tree. "./..." pulls all Go files in the tree as packages,
	// which addresses the sibling-symbol-missing class of failures from the
	// pilot — multi-file packages now resolve cleanly.
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, meta, fmt.Errorf("failed to execute loader: %w", err)
	}

	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			meta.LoadErrors = append(meta.LoadErrors, e.Error())
		}
	})

	return pkgs, meta, nil
}

// findGoMod walks up from dir looking for a go.mod file. Returns the directory
// containing it and the module path, or ("", "") if none found.
func findGoMod(dir string) (modDir, modPath string) {
	for {
		modFile := filepath.Join(dir, "go.mod")
		if data, err := os.ReadFile(modFile); err == nil {
			if mp := parseModuleLine(data); mp != "" {
				return dir, mp
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ""
		}
		dir = parent
	}
}

// parseModuleLine extracts the module path from go.mod's `module <path>` line.
// Lightweight string scan — sufficient for the path-only field.
func parseModuleLine(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "module") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		// Strip surrounding quotes if present (rare but valid).
		rest = strings.Trim(rest, "\"`")
		// Strip an inline comment.
		if i := strings.Index(rest, "//"); i >= 0 {
			rest = strings.TrimSpace(rest[:i])
		}
		if rest != "" {
			return rest
		}
	}
	return ""
}

// syntheticModulePath returns the stable module path used by the
// overlay-synthesized go.mod when a tree has no real go.mod. The path
// MUST be stable across loads — pairwise diff comparisons load each
// side from its own temp directory, and per-load variation in the
// module path makes type qualifiers (e.g. on user-defined types like
// "synthetic.local/A.Foo" vs "synthetic.local/B.Foo") asymmetric across
// sides, deflating types.Type.String()-based similarity. A constant
// prevents that — both halves of any pairwise comparison see identical
// qualifiers for identical types.
//
// See FingerprintTree's KNOWN LIMITATION note: this constant works for
// self-contained single-package trees but does not resolve same-module
// sub-package imports in real multi-package trees, where source imports
// the real module path and the synthetic "synthetic.local/anonymous"
// identity cannot satisfy those lookups; callers that know the real module
// path pass it as TreeLoadOptions.ModuleNameHint.
func syntheticModulePath() string {
	return "synthetic.local/anonymous"
}
