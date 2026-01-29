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

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
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
