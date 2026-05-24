package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/ir"
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

func GenerateFingerprint(fn *ssa.Function, policy ir.LiteralPolicy, strictMode bool) FingerprintResult {
	line := 0
	filename := ""
	if fn.Prog != nil && fn.Prog.Fset != nil {
		p := fn.Prog.Fset.Position(fn.Pos())
		line = p.Line
		filename = p.Filename
	}

	if len(fn.Blocks) > MaxFunctionBlocks {
		return FingerprintResult{
			FunctionName: fn.RelString(nil),
			Fingerprint:  "OVERSIZED",
			CanonicalIR:  fmt.Sprintf("; Skipped: Function too large (%d blocks > %d)", len(fn.Blocks), MaxFunctionBlocks),
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
	initialPkgs, err := loadPackagesFromSource(filename, src)
	if err != nil {
		return nil, err
	}

	return FingerprintPackages(initialPkgs, policy, strictMode)
}

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

	fset := token.NewFileSet()

	cfg := &packages.Config{
		Dir:  sourceDir,
		Mode: packages.LoadAllSyntax,
		Fset: fset,
		Overlay: map[string][]byte{
			absFilename: []byte(src),
		},
		Tests: false,
		Env:   GetHardenedEnv(),
	}

	initialPkgs, err := packages.Load(cfg, "file="+absFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to execute loader: %w", err)
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

func FingerprintPackages(initialPkgs []*packages.Package, policy ir.LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	if len(initialPkgs) == 0 {
		return nil, fmt.Errorf("input packages list is empty")
	}

	prog, _, err := ir.BuildSSAFromPackages(initialPkgs)
	if err != nil {
		return nil, fmt.Errorf("failed to build SSA: %w", err)
	}

	var results []FingerprintResult
	visited := make(map[*ssa.Function]bool)

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
				processFunctionAndAnons(mem, policy, strictMode, &results, visited)
			case *ssa.Type:
				if named, ok := mem.Type().(*types.Named); ok {
					for i := 0; i < named.NumMethods(); i++ {
						m := named.Method(i)
						if fn := prog.FuncValue(m); fn != nil {
							processFunctionAndAnons(fn, policy, strictMode, &results, visited)
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

func processFunctionAndAnons(fn *ssa.Function, policy ir.LiteralPolicy, strictMode bool, results *[]FingerprintResult, visited map[*ssa.Function]bool) {
	if visited[fn] {
		return
	}
	visited[fn] = true

	if fn.Synthetic != "" && fn.Name() != "init" {
		return
	}

	if len(fn.Blocks) > 0 {
		result := GenerateFingerprint(fn, policy, strictMode)
		*results = append(*results, result)
	}

	for _, anon := range fn.AnonFuncs {
		processFunctionAndAnons(anon, policy, strictMode, results, visited)
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
	// hardening applied by GetHardenedEnv (CGO_ENABLED=0, GOWORK=off, etc.)
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
// declaring the REAL module name placed at the worktree root would resolve
// the imports correctly. The fix shape — adding a moduleNameHint parameter
// and loading the target package(s) by module-relative path from the tree
// root — is mechanism-verified but implementation-deferred. Affected
// corpus: pre-modules-era multi-package trees (modern commits carry their
// own go.mod and don't go through this synthesis path).
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
// identity cannot satisfy those lookups. The verified-deferred fix is a
// moduleNameHint parameter on FingerprintTreeAdvanced.
func syntheticModulePath() string {
	return "synthetic.local/anonymous"
}
