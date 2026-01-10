package semanticfw

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// Encapsulates the output of the semantic fingerprinting process for a function.
type FingerprintResult struct {
	FunctionName string
	Fingerprint  string
	CanonicalIR  string
	Pos          token.Pos
	Line         int
	Filename     string
}

// Normalizes conditional branches to ensure consistent graph structure.
func normalizeControlFlow(fn *ssa.Function) {
	for _, block := range fn.Blocks {
		if len(block.Instrs) == 0 {
			continue
		}
		// Check if the last instruction is an If
		if ifInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If); ok {
			// Check if the condition is a BinOp
			if binOp, ok := ifInstr.Cond.(*ssa.BinOp); ok {

				// BUG FIX: Do not invert floating point or complex comparisons as it changes logic for NaN.
				// NaN >= x is False, NaN < x is False. Swapping branches assumes inversion holds.
				// Complex numbers have similar issues with undefined ordering.
				if basic, ok := binOp.X.Type().Underlying().(*types.Basic); ok && ((basic.Info()&types.IsFloat) != 0 || (basic.Info()&types.IsComplex) != 0) {
					continue
				}

				// BUG FIX: Do not mutate BinOp if it has multiple referrers.
				// If the condition is stored in a variable and used elsewhere (e.g., returned),
				// mutating the operator corrupts the semantics of those other uses.
				if refs := binOp.Referrers(); refs != nil && len(*refs) > 1 {
					continue
				}

				var newOp token.Token
				swap := false
				switch binOp.Op {
				case token.GEQ: // >= becomes <
					newOp = token.LSS
					swap = true
				case token.GTR: // > becomes <=
					newOp = token.LEQ
					swap = true
				}

				if swap {
					// BUG FIX: Defensive check to ensure exactly 2 successors before swapping
					if len(block.Succs) != 2 {
						continue
					}
					// Mutate the operator in place - this is safe because we're also
					// swapping the successors to maintain correct semantics.
					binOp.Op = newOp

					// Swap successors
					block.Succs[0], block.Succs[1] = block.Succs[1], block.Succs[0]
				}
			}
		}
	}
}

// Generates the hash and canonical string representation for an SSA function.
func GenerateFingerprint(fn *ssa.Function, policy LiteralPolicy, strictMode bool) FingerprintResult {
	normalizeControlFlow(fn)

	canonicalizer := NewCanonicalizer(policy)
	canonicalizer.StrictMode = strictMode
	canonicalIR := canonicalizer.CanonicalizeFunction(fn)

	hash := sha256.Sum256([]byte(canonicalIR))
	fingerprint := hex.EncodeToString(hash[:])

	// BUG FIX: Resolve position information here while Fset is available.
	line := 0
	filename := ""
	if fn.Prog != nil && fn.Prog.Fset != nil {
		p := fn.Prog.Fset.Position(fn.Pos())
		line = p.Line
		filename = p.Filename
	}

	return FingerprintResult{
		// BUG FIX: Use RelString(nil) to get fully qualified names (e.g. (*Type).Method).
		FunctionName: fn.RelString(nil),
		Fingerprint:  fingerprint,
		CanonicalIR:  canonicalIR,
		Pos:          fn.Pos(),
		Line:         line,
		Filename:     filename,
	}
}

// Analyzes a single Go source file provided as a string.
// This is the primary entry point for verifying code snippets or patch hunks.
func FingerprintSource(filename string, src string, policy LiteralPolicy) ([]FingerprintResult, error) {
	return FingerprintSourceAdvanced(filename, src, policy, false)
}

// Provides an extended interface for source analysis with strict mode control.
func FingerprintSourceAdvanced(filename string, src string, policy LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	initialPkgs, err := loadPackagesFromSource(filename, src)
	if err != nil {
		return nil, err
	}

	return FingerprintPackages(initialPkgs, policy, strictMode)
}

// Loads packages from a provided source string for analysis.
func loadPackagesFromSource(filename string, src string) ([]*packages.Package, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("input source code is empty")
	}

	sourceDir := filepath.Dir(filename)
	absFilename, err := filepath.Abs(filename)
	if err != nil {
		absFilename = filename
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

	if errorMessages.Len() > 0 {
		return nil, fmt.Errorf("packages contain errors: \n%s", errorMessages.String())
	}

	return initialPkgs, nil
}

// Iterates over loaded packages to construct SSA and generate results.
func FingerprintPackages(initialPkgs []*packages.Package, policy LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	if len(initialPkgs) == 0 {
		return nil, fmt.Errorf("input packages list is empty")
	}

	prog, _, err := BuildSSAFromPackages(initialPkgs)
	if err != nil {
		return nil, fmt.Errorf("failed to build SSA: %w", err)
	}

	var results []FingerprintResult

	// BUG FIX: Iterate over all packages provided, not just the main one.
	for _, pkg := range initialPkgs {
		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}

		for _, member := range ssaPkg.Members {
			switch mem := member.(type) {
			case *ssa.Function:
				// Top-level functions (and init)
				processFunctionAndAnons(mem, policy, strictMode, &results)
			case *ssa.Type:
				// BUG FIX: Explicitly handle methods associated with named types.
				if named, ok := mem.Type().(*types.Named); ok {
					for i := 0; i < named.NumMethods(); i++ {
						m := named.Method(i)
						if fn := prog.FuncValue(m); fn != nil {
							processFunctionAndAnons(fn, policy, strictMode, &results)
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

// Recursively analyzes a function and its nested closures.
func processFunctionAndAnons(fn *ssa.Function, policy LiteralPolicy, strictMode bool, results *[]FingerprintResult) {
	if fn.Synthetic == "" {
		if len(fn.Blocks) > 0 {
			result := GenerateFingerprint(fn, policy, strictMode)
			*results = append(*results, result)
		}
	}

	for _, anon := range fn.AnonFuncs {
		processFunctionAndAnons(anon, policy, strictMode, results)
	}
}
