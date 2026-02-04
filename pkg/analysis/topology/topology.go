package topology

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/loop"
	"golang.org/x/tools/go/ssa"
)

// FunctionTopology captures the structural "shape" of a function independent of names.
type FunctionTopology struct {
	FuzzyHash string

	// Basic metrics
	ParamCount  int
	ReturnCount int
	BlockCount  int
	InstrCount  int
	LoopCount   int
	BranchCount int // if statements
	PhiCount    int

	// Complexity metrics
	CyclomaticComplexity int

	// Call profile: map of "package.func" or "method" -> count
	CallSignatures map[string]int

	// Granular instruction tracking
	InstrCounts map[string]int

	// Type signature (normalized)
	ParamTypes  []string
	ReturnTypes []string

	// Control flow features
	HasDefer   bool
	HasRecover bool
	HasPanic   bool
	HasGo      bool
	HasSelect  bool
	HasRange   bool

	// Operator profile
	BinOpCounts map[string]int
	UnOpCounts  map[string]int

	// String literal hashes (for behavioral matching)
	StringLiterals []string

	// Entropy analysis for obfuscation detection
	EntropyScore   float64
	EntropyProfile EntropyProfile

	// The underlying function (internal use)
	fn *ssa.Function
}

var (
	// Hardening: Prevent Memory DoS from massive string literals
	// These limits can be adjusted via SetTopologyLimits.
	// Protected by configMu to prevent data races.
	configMu            sync.RWMutex
	MaxStringLiteralLen = 4096      // 4KB limit per string
	MaxTotalStringBytes = 1024 * 64 // 64KB limit per function

	// Regex to properly strip package paths without removing type modifiers (*, [], map)
	// Matches sequences like "github.com/pkg/" or "net/http/"
	typePathCleaner = regexp.MustCompile(`[\w.-]+/`)
)

// SetTopologyLimits adjusts the memory safeguards for string processing.
func SetTopologyLimits(maxLen, maxTotal int) {
	configMu.Lock()
	defer configMu.Unlock()
	MaxStringLiteralLen = maxLen
	MaxTotalStringBytes = maxTotal
}

// ExtractTopology analyzes an SSA function and extracts its structural features.
func ExtractTopology(fn *ssa.Function) *FunctionTopology {
	if fn == nil || len(fn.Blocks) == 0 {
		return nil
	}

	// Snapshot configuration safely to prevent data races during analysis
	configMu.RLock()
	maxStrLen := MaxStringLiteralLen
	maxTotalBytes := MaxTotalStringBytes
	configMu.RUnlock()

	t := &FunctionTopology{
		fn:             fn,
		ParamCount:     len(fn.Params),
		BlockCount:     len(fn.Blocks),
		CallSignatures: make(map[string]int),
		InstrCounts:    make(map[string]int),
		BinOpCounts:    make(map[string]int),
		UnOpCounts:     make(map[string]int),
		ParamTypes:     make([]string, 0, len(fn.Params)),
		ReturnTypes:    make([]string, 0),
	}

	for _, p := range fn.Params {
		t.ParamTypes = append(t.ParamTypes, normalizeTypeName(p.Type()))
	}

	sig := fn.Signature
	results := sig.Results()
	t.ReturnCount = results.Len()
	for i := 0; i < results.Len(); i++ {
		t.ReturnTypes = append(t.ReturnTypes, normalizeTypeName(results.At(i).Type()))
	}

	loopInfo := loop.DetectLoops(fn)
	t.LoopCount = loop.CountLoops(loopInfo.Loops)

	// Analyze AST for additional loop constructs.
	// Fallback for broken CFGs
	// SSA often drops back edges in these cases.
	if fn.Syntax() != nil {
		astLoops := 0
		root := fn.Syntax()
		ast.Inspect(root, func(n ast.Node) bool {
			// Bug Fix: Prevent recursion into nested closures.
			// SSA handles closures as separate functions; we must not count their loops here.
			// We only count loops belonging to the current function scope.
			if n != root {
				if _, isClosure := n.(*ast.FuncLit); isClosure {
					return false
				}
			}

			switch n.(type) {
			case *ast.ForStmt, *ast.RangeStmt:
				astLoops++
			}
			return true
		})

		// Security Heuristic: Trust the higher complexity.
		if astLoops > t.LoopCount {
			t.LoopCount = astLoops
		}
	}

	currentStringBytes := 0
	edgeCount := 0

	for _, block := range fn.Blocks {
		t.InstrCount += len(block.Instrs)
		edgeCount += len(block.Succs)

		for _, instr := range block.Instrs {
			// Track exact instruction types for granular similarity
			t.InstrCounts[fmt.Sprintf("%T", instr)]++

			switch i := instr.(type) {
			case *ssa.If:
				t.BranchCount++
			case *ssa.Phi:
				t.PhiCount++
			case *ssa.Call:
				sig := extractCallSignature(i)
				t.CallSignatures[sig]++
			case *ssa.Go:
				t.HasGo = true
				sig := extractGoSignature(i)
				t.CallSignatures["go:"+sig]++
			case *ssa.Defer:
				t.HasDefer = true
				sig := extractDeferSignature(i)
				t.CallSignatures["defer:"+sig]++
			case *ssa.Panic:
				t.HasPanic = true
			case *ssa.Select:
				t.HasSelect = true
			case *ssa.Range:
				t.HasRange = true
			case *ssa.BinOp:
				t.BinOpCounts[i.Op.String()]++
			case *ssa.UnOp:
				t.UnOpCounts[i.Op.String()]++
			}

			for _, op := range instr.Operands(nil) {
				if op == nil || *op == nil {
					continue
				}
				if c, ok := (*op).(*ssa.Const); ok && c.Value != nil {
					if c.Value.Kind() == constant.String {
						val := constant.StringVal(c.Value)

						if len(val) > maxStrLen {
							val = val[:maxStrLen]
						}

						// Security Fix: Prevent DoS via O(N^2) ValidString checks on binary data.
						// Perform a linear scan O(N) to find the longest valid UTF-8 prefix.
						if !utf8.ValidString(val) {
							validLen := 0
							for i := 0; i < len(val); {
								r, size := utf8.DecodeRuneInString(val[i:])
								if r == utf8.RuneError && size == 1 {
									break // Stop at first invalid byte
								}
								validLen += size
								i += size
							}
							val = val[:validLen]
						}

						if currentStringBytes+len(val) <= maxTotalBytes {
							t.StringLiterals = append(t.StringLiterals, val)
							currentStringBytes += len(val)
						}
					}
				}
			}
		}
	}

	// Calculate Cyclomatic Complexity: M = E - N + 2P
	// For a single function, P (connected components) is usually 1.
	t.CyclomaticComplexity = edgeCount - t.BlockCount + 2

	if t.HasDefer {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				if call, ok := instr.(*ssa.Call); ok {
					if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
						if builtin.Name() == "recover" {
							t.HasRecover = true
						}
					}
				}
			}
		}
	}

	// Use sort.SliceStable for deterministic string ordering
	sort.SliceStable(t.StringLiterals, func(i, j int) bool {
		return t.StringLiterals[i] < t.StringLiterals[j]
	})

	dataAccumulator := flattenStringLiterals(t.StringLiterals)

	if len(dataAccumulator) > 0 {
		t.EntropyScore = CalculateEntropy(dataAccumulator)
		t.EntropyProfile = CalculateEntropyProfile(dataAccumulator, t.StringLiterals)
	} else {
		t.EntropyScore = 0
		t.EntropyProfile = EntropyProfile{Classification: EntropyLow}
	}

	// Generate hash last so all metrics are populated
	t.FuzzyHash = GenerateFuzzyHash(t)

	return t
}

// GenerateFuzzyHash creates a short representation of the function structure.
func GenerateFuzzyHash(t *FunctionTopology) string {
	bBucket := 0
	if t.BlockCount > 0 {
		bBucket = int(math.Log2(float64(t.BlockCount)))
	}
	brBucket := 0
	if t.BranchCount > 0 {
		// FIX: Differentiate between 0 branches (linear) and 1 branch (single if).
		// Log2(1) is 0, so we shift by 1 to make BR0 mean "no branches" and BR1 mean "1 branch".
		brBucket = int(math.Log2(float64(t.BranchCount))) + 1
	}
	lBucket := t.LoopCount
	if lBucket > 5 {
		lBucket = 5
	}

	// Format: B{BlockLog2}L{LoopCap}BR{BranchLog2}P{ParamCount}R{ReturnCount}
	// Example: B2L0BR1P2R1
	return fmt.Sprintf("B%dL%dBR%dP%dR%d", bBucket, lBucket, brBucket, t.ParamCount, t.ReturnCount)
}

func normalizeTypeName(t types.Type) string {
	s := t.String()
	// Fix: Use regex to remove package paths (e.g., "github.com/pkg/")
	// instead of finding the last slash, which incorrectly strips type
	// modifiers like * (pointer) or map[...] that appear before the path.
	return typePathCleaner.ReplaceAllString(s, "")
}

func extractCallSignature(call *ssa.Call) string {
	if call.Call.IsInvoke() {
		recvType := call.Call.Value.Type()
		return fmt.Sprintf("invoke:%s.%s", normalizeTypeName(recvType), call.Call.Method.Name())
	}

	switch v := call.Call.Value.(type) {
	case *ssa.Function:
		return extractFunctionSig(v)
	case *ssa.Builtin:
		return fmt.Sprintf("builtin:%s", v.Name())
	case *ssa.MakeClosure:
		// FIX: Use Safe Type Assertion to avoid panic
		if fn, ok := v.Fn.(*ssa.Function); ok && fn != nil {
			return fmt.Sprintf("closure:%s", fn.Signature.String())
		}
	}

	if call.Call.Value != nil {
		typeStr := call.Call.Value.Type().String()
		if strings.Contains(typeStr, "reflect.Value") {
			return "reflect:Call"
		}
		return fmt.Sprintf("dynamic:%s", normalizeTypeName(call.Call.Value.Type()))
	}
	return "call:unknown"
}

func extractGoSignature(g *ssa.Go) string {
	// FIX: Handle interface method invocations (go w.Do())
	// In Invoke mode, Value is the receiver.
	if g.Call.IsInvoke() {
		recvType := g.Call.Value.Type()
		return fmt.Sprintf("invoke:%s.%s", normalizeTypeName(recvType), g.Call.Method.Name())
	}

	switch v := g.Call.Value.(type) {
	case *ssa.Function:
		return extractFunctionSig(v)
	case *ssa.MakeClosure:
		// FIX: Use Safe Type Assertion
		if fn, ok := v.Fn.(*ssa.Function); ok && fn != nil {
			return fmt.Sprintf("closure:%s", fn.Signature.String())
		}
	}
	// Fallback for dynamic function pointers
	if g.Call.Value != nil {
		return fmt.Sprintf("dynamic:%s", normalizeTypeName(g.Call.Value.Type()))
	}
	return "unknown"
}

func extractDeferSignature(d *ssa.Defer) string {
	// FIX: Handle interface method invocations (defer w.Close())
	if d.Call.IsInvoke() {
		recvType := d.Call.Value.Type()
		return fmt.Sprintf("invoke:%s.%s", normalizeTypeName(recvType), d.Call.Method.Name())
	}

	switch v := d.Call.Value.(type) {
	case *ssa.Function:
		return extractFunctionSig(v)
	case *ssa.MakeClosure:
		// FIX: Use Safe Type Assertion
		if fn, ok := v.Fn.(*ssa.Function); ok && fn != nil {
			return fmt.Sprintf("closure:%s", fn.Signature.String())
		}
	}
	if d.Call.Value != nil {
		return fmt.Sprintf("dynamic:%s", normalizeTypeName(d.Call.Value.Type()))
	}
	return "unknown"
}

func extractFunctionSig(fn *ssa.Function) string {
	// Fix: Detect anonymous/nested functions to provide stable signatures.
	// This handles optimizations where simple closures become plain Functions.
	if fn.Parent() != nil {
		return fmt.Sprintf("closure:%s", fn.Signature.String())
	}

	if fn.Pkg != nil {
		pkgName := fn.Pkg.Pkg.Name()
		return fmt.Sprintf("%s.%s", pkgName, fn.Name())
	}
	return fn.RelString(nil)
}

// TopologySimilarity calculates the similarity between two function topologies.
func TopologySimilarity(a, b *FunctionTopology) float64 {
	if a == nil || b == nil {
		return 0.0
	}

	var score float64
	var weights float64

	paramScore := typeListSimilarity(a.ParamTypes, b.ParamTypes)
	score += paramScore * 3.0
	weights += 3.0

	returnScore := typeListSimilarity(a.ReturnTypes, b.ReturnTypes)
	score += returnScore * 2.0
	weights += 2.0

	if a.LoopCount == b.LoopCount {
		score += 2.0
	} else if abs(a.LoopCount-b.LoopCount) == 1 {
		score += 1.0
	}
	weights += 2.0

	branchDiff := abs(a.BranchCount - b.BranchCount)
	maxBranch := intMax(a.BranchCount, b.BranchCount)
	// Guard against division by zero (0/0 = perfect match logic for this context)
	if maxBranch > 0 {
		score += (1.0 - float64(branchDiff)/float64(maxBranch)) * 1.5
	} else {
		score += 1.5
	}
	weights += 1.5

	callScore := MapSimilarity(a.CallSignatures, b.CallSignatures)
	score += callScore * 4.0
	weights += 4.0

	binOpScore := MapSimilarity(a.BinOpCounts, b.BinOpCounts)
	score += binOpScore * 1.0
	weights += 1.0

	// Detailed instruction counts provide finer granularity
	instrScore := MapSimilarity(a.InstrCounts, b.InstrCounts)
	score += instrScore * 0.5
	weights += 0.5

	boolScore := 0.0
	boolCount := 0.0
	boolScore += boolMatch(a.HasDefer, b.HasDefer)
	boolCount++
	boolScore += boolMatch(a.HasPanic, b.HasPanic)
	boolCount++
	boolScore += boolMatch(a.HasGo, b.HasGo)
	boolCount++
	boolScore += boolMatch(a.HasSelect, b.HasSelect)
	boolCount++
	boolScore += boolMatch(a.HasRange, b.HasRange)
	boolCount++
	score += (boolScore / boolCount) * 1.0
	weights += 1.0

	blockDiff := abs(a.BlockCount - b.BlockCount)
	maxBlock := intMax(a.BlockCount, b.BlockCount)
	// Guard against division by zero
	if maxBlock > 0 {
		score += (1.0 - float64(blockDiff)/float64(maxBlock*2)) * 0.5
	} else {
		score += 0.5
	}
	weights += 0.5

	return score / weights
}

func typeListSimilarity(a, b []string) float64 {
	// FIX: Robust similarity using Dice coefficient
	// Previous implementation returned 0.0 if lengths differed, causing
	// near-identical functions (e.g. one extra param) to have 0 similarity.
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	matches := 0
	minLen := intMin(len(a), len(b))
	for i := 0; i < minLen; i++ {
		if a[i] == b[i] {
			matches++
		}
	}

	// Dice coefficient: 2*matches / (lenA + lenB)
	return 2.0 * float64(matches) / float64(len(a)+len(b))
}

// MapSimilarity calculates the similarity between two frequency maps.
func MapSimilarity(a, b map[string]int) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	intersection := 0
	union := 0

	for k, countA := range a {
		countB := b[k]
		intersection += intMin(countA, countB)
		union += intMax(countA, countB)
	}

	for k, countB := range b {
		if _, exists := a[k]; !exists {
			union += countB
		}
	}

	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

func boolMatch(a, b bool) float64 {
	if a == b {
		return 1.0
	}
	return 0.0
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func intMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TopologyFingerprint(t *FunctionTopology) string {
	if t == nil {
		return "nil"
	}

	var calls []string
	for sig := range t.CallSignatures {
		calls = append(calls, sig)
	}
	sort.Strings(calls)

	callStr := ""
	if len(calls) > 0 {
		if len(calls) > 3 {
			callStr = fmt.Sprintf("%s,...(%d)", strings.Join(calls[:3], ","), len(calls))
		} else {
			callStr = strings.Join(calls, ",")
		}
	}

	return fmt.Sprintf("L%dB%dI%d[%s]", t.LoopCount, t.BranchCount, t.InstrCount, callStr)
}

func flattenStringLiterals(literals []string) []byte {
	totalSize := 0
	for _, s := range literals {
		// With StringVal, we no longer need to strip quotes manually, but we keep logic simple
		totalSize += len(s)
	}

	dataAccumulator := make([]byte, 0, totalSize)
	for _, s := range literals {
		dataAccumulator = append(dataAccumulator, s...)
	}
	return dataAccumulator
}
