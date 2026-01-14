package semanticfw

import (
	"fmt"
	"go/constant"
	"go/types"
	"math"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Captures the structural "shape" of a function independent of names.
// This enables matching functions that have been renamed or obfuscated.
type FunctionTopology struct {
	// Fuzzy Hash for Bucket Indexing (LSH-lite)
	// Used for O(1) candidate retrieval in large databases.
	FuzzyHash string

	// Basic metrics
	ParamCount  int
	ReturnCount int
	BlockCount  int
	InstrCount  int
	LoopCount   int
	BranchCount int // if statements
	PhiCount    int

	// Call profile: map of "package.func" or "method" -> count
	CallSignatures map[string]int

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
	EntropyScore   float64        // Shannon entropy of function body (0.0-8.0)
	EntropyProfile EntropyProfile // Full entropy analysis

	// The underlying function (internal use)
	fn *ssa.Function
}

// Analyzes an SSA function and extracts its structural features.
func ExtractTopology(fn *ssa.Function) *FunctionTopology {
	if fn == nil || len(fn.Blocks) == 0 {
		return nil
	}

	t := &FunctionTopology{
		fn:             fn,
		ParamCount:     len(fn.Params),
		BlockCount:     len(fn.Blocks),
		CallSignatures: make(map[string]int),
		BinOpCounts:    make(map[string]int),
		UnOpCounts:     make(map[string]int),
		ParamTypes:     make([]string, 0, len(fn.Params)),
		ReturnTypes:    make([]string, 0),
	}

	// Extract parameter types
	for _, p := range fn.Params {
		t.ParamTypes = append(t.ParamTypes, normalizeTypeName(p.Type()))
	}

	// Extract return types from signature
	sig := fn.Signature
	results := sig.Results()
	t.ReturnCount = results.Len()
	for i := 0; i < results.Len(); i++ {
		t.ReturnTypes = append(t.ReturnTypes, normalizeTypeName(results.At(i).Type()))
	}

	// Detect loops
	loopInfo := DetectLoops(fn)
	t.LoopCount = countLoops(loopInfo.Loops)

	// Analyze all instructions
	for _, block := range fn.Blocks {
		t.InstrCount += len(block.Instrs)

		for _, instr := range block.Instrs {
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

			// REMEDIATION: Naive Entropy Fix
			// Target specific string literals; ignore SSA IR verbosity.
			for _, op := range instr.Operands(nil) {
				if op == nil || *op == nil {
					continue
				}
				if c, ok := (*op).(*ssa.Const); ok && c.Value != nil {
					if c.Value.Kind() == constant.String {
						t.StringLiterals = append(t.StringLiterals, c.Value.ExactString())
					}
				}
			}
		}
	}

	// Check for recover in defers (simple heuristic)
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

	// Sort string literals for deterministic comparison
	sort.Strings(t.StringLiterals)

	// REMEDIATION: Naive Entropy Fix
	// Calculate entropy on pure data segments to prevent dilution by verbose IR instructions.
	// Pre-calculate total size to avoid repeated allocations
	totalSize := 0
	for _, s := range t.StringLiterals {
		// Account for quote stripping
		totalSize += len(s) - 2 // Subtract 2 for potential quotes
		if totalSize < 0 {
			totalSize = len(s)
		}
	}
	
	dataAccumulator := make([]byte, 0, totalSize)
	for _, s := range t.StringLiterals {
		// Strip quotes for raw data analysis
		raw := strings.Trim(s, "\"`")
		dataAccumulator = append(dataAccumulator, []byte(raw)...)
	}

	// If no data, the function has 0 entropy (pure logic).
	if len(dataAccumulator) > 0 {
		t.EntropyScore = CalculateEntropy(dataAccumulator)
		t.EntropyProfile = CalculateEntropyProfile(dataAccumulator, t.StringLiterals)
	} else {
		t.EntropyScore = 0
		t.EntropyProfile = EntropyProfile{Classification: EntropyLow}
	}

	// REMEDIATION: O(1) Topology Trap Fix
	// Generates a Fuzzy Bucket Hash (LSH-lite) for efficient indexing.
	t.FuzzyHash = GenerateFuzzyHash(t)

	return t
}

// REMEDIATION: O(1) Topology Trap Fix
// GenerateFuzzyHash creates a locality-sensitive hash for bucket indexing.
// Buckets: Blocks (Log2), Loops (Exact/Capped), Branches (Log2).
func GenerateFuzzyHash(t *FunctionTopology) string {
	// Quantize metrics to create stable buckets
	// Log2 buckets reduce sensitivity to small changes in larger functions
	bBucket := 0
	if t.BlockCount > 0 {
		bBucket = int(math.Log2(float64(t.BlockCount)))
	}
	brBucket := 0
	if t.BranchCount > 0 {
		brBucket = int(math.Log2(float64(t.BranchCount)))
	}
	// Loop count is critical structural feature, keep exact or capped
	lBucket := t.LoopCount
	if lBucket > 5 {
		lBucket = 5 // Cap at 5+
	}

	return fmt.Sprintf("B%dL%dBR%d", bBucket, lBucket, brBucket)
}

// Converts a type to a canonical string, stripping package paths.
func normalizeTypeName(t types.Type) string {
	s := t.String()
	// Strip package paths for comparison (e.g., "github.com/foo/bar.Type" -> "bar.Type")
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		s = s[idx+1:]
	}
	return s
}

// REMEDIATION: Call Signature Fragility Fix
// Resolve interface methods and reflection targets.
func extractCallSignature(call *ssa.Call) string {
	if call.Call.IsInvoke() {
		// Method call on interface: include Interface Type Name + Method Name
		// This makes signatures robust against implementation changes.
		recvType := call.Call.Value.Type()
		return fmt.Sprintf("invoke:%s.%s", normalizeTypeName(recvType), call.Call.Method.Name())
	}

	switch v := call.Call.Value.(type) {
	case *ssa.Function:
		return extractFunctionSig(v)
	case *ssa.Builtin:
		return fmt.Sprintf("builtin:%s", v.Name())
	case *ssa.MakeClosure:
		if fn := v.Fn.(*ssa.Function); fn != nil {
			return fmt.Sprintf("closure:%s", fn.Signature.String())
		}
	}

	// Detect Reflection: call.Call.Value might be a method value like reflect.Value.Call
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
	switch v := g.Call.Value.(type) {
	case *ssa.Function:
		return extractFunctionSig(v)
	case *ssa.MakeClosure:
		if fn := v.Fn.(*ssa.Function); fn != nil {
			return fmt.Sprintf("closure:%s", fn.Signature.String())
		}
	}
	return "unknown"
}

func extractDeferSignature(d *ssa.Defer) string {
	switch v := d.Call.Value.(type) {
	case *ssa.Function:
		return extractFunctionSig(v)
	case *ssa.MakeClosure:
		if fn := v.Fn.(*ssa.Function); fn != nil {
			return fmt.Sprintf("closure:%s", fn.Signature.String())
		}
	}
	if d.Call.IsInvoke() {
		return fmt.Sprintf("invoke:%s", d.Call.Method.Name())
	}
	return "unknown"
}

func extractFunctionSig(fn *ssa.Function) string {
	if fn.Pkg != nil {
		// Use package name (not path) + function name
		pkgName := fn.Pkg.Pkg.Name()
		return fmt.Sprintf("%s.%s", pkgName, fn.Name())
	}
	// Might be a method or closure
	return fn.RelString(nil)
}

func countLoops(loops []*Loop) int {
	count := len(loops)
	for _, l := range loops {
		count += countLoops(l.Children)
	}
	return count
}

// Computes a similarity score between two function topologies.
// Returns a value between 0.0 (completely different) and 1.0 (identical structure).
func TopologySimilarity(a, b *FunctionTopology) float64 {
	if a == nil || b == nil {
		return 0.0
	}

	var score float64
	var weights float64

	// Weight 1: Parameter signature match (high importance)
	paramScore := typeListSimilarity(a.ParamTypes, b.ParamTypes)
	score += paramScore * 3.0
	weights += 3.0

	// Weight 2: Return signature match (high importance)
	returnScore := typeListSimilarity(a.ReturnTypes, b.ReturnTypes)
	score += returnScore * 2.0
	weights += 2.0

	// Weight 3: Loop count similarity (critical for control flow)
	if a.LoopCount == b.LoopCount {
		score += 2.0
	} else if abs(a.LoopCount-b.LoopCount) == 1 {
		score += 1.0
	}
	weights += 2.0

	// Weight 4: Branch count similarity
	branchDiff := abs(a.BranchCount - b.BranchCount)
	maxBranch := max(a.BranchCount, b.BranchCount)
	if maxBranch > 0 {
		score += (1.0 - float64(branchDiff)/float64(maxBranch)) * 1.5
	} else {
		score += 1.5
	}
	weights += 1.5

	// Weight 5: Call signature overlap (VERY important for malware detection)
	callScore := mapSimilarity(a.CallSignatures, b.CallSignatures)
	score += callScore * 4.0
	weights += 4.0

	// Weight 6: Operator profile similarity
	binOpScore := mapSimilarity(a.BinOpCounts, b.BinOpCounts)
	score += binOpScore * 1.0
	weights += 1.0

	// Weight 7: Boolean feature match
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

	// Weight 8: Block count similarity (rough size match)
	blockDiff := abs(a.BlockCount - b.BlockCount)
	maxBlock := max(a.BlockCount, b.BlockCount)
	if maxBlock > 0 {
		score += (1.0 - float64(blockDiff)/float64(maxBlock*2)) * 0.5
	}
	weights += 0.5

	return score / weights
}

func typeListSimilarity(a, b []string) float64 {
	if len(a) != len(b) {
		// Length mismatch is a strong negative signal
		return 0.0
	}
	if len(a) == 0 {
		return 1.0
	}
	matches := 0
	for i := range a {
		if a[i] == b[i] {
			matches++
		}
	}
	return float64(matches) / float64(len(a))
}

func mapSimilarity(a, b map[string]int) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	// Single-pass algorithm: iterate once through both maps
	intersection := 0
	union := 0
	
	// First pass: process all keys in map 'a'
	for k, countA := range a {
		countB := b[k]
		intersection += min(countA, countB)
		union += max(countA, countB)
	}
	
	// Second pass: process keys only in map 'b'
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

// Represents a potential function pairing with a confidence score.
type TopologyMatch struct {
	OldResult   FingerprintResult
	NewResult   FingerprintResult
	OldTopology *FunctionTopology
	NewTopology *FunctionTopology
	Similarity  float64
	ByName      bool // true if matched by name, false if by topology
}

// Performs topology based function matching between two sets of fingerprint results.
// This is the "unobfuscator" that finds renamed functions.
//
// Strategy:
// 1. First, try to match by exact name (preserves intentional naming)
// 2. For unmatched functions, compute topology similarity matrix
// 3. Use greedy matching to pair functions by structural similarity
// 4. Report matches above a confidence threshold
func MatchFunctionsByTopology(oldResults, newResults []FingerprintResult, threshold float64) (
	matched []TopologyMatch,
	addedFuncs []FingerprintResult,
	removedFuncs []FingerprintResult,
) {
	// Build name lookup maps
	oldByName := make(map[string]FingerprintResult)
	newByName := make(map[string]FingerprintResult)

	for _, r := range oldResults {
		shortName := shortFuncName(r.FunctionName)
		oldByName[shortName] = r
	}
	for _, r := range newResults {
		shortName := shortFuncName(r.FunctionName)
		newByName[shortName] = r
	}

	// Track what's been matched
	matchedOld := make(map[string]bool)
	matchedNew := make(map[string]bool)

	// Phase 1: Match by exact name
	for name, oldR := range oldByName {
		if newR, ok := newByName[name]; ok {
			oldFn := oldR.GetSSAFunction()
			newFn := newR.GetSSAFunction()

			var oldTopo, newTopo *FunctionTopology
			if oldFn != nil {
				oldTopo = ExtractTopology(oldFn)
			}
			if newFn != nil {
				newTopo = ExtractTopology(newFn)
			}

			sim := 1.0 // Name match implies high confidence
			if oldTopo != nil && newTopo != nil {
				sim = TopologySimilarity(oldTopo, newTopo)
			}

			matched = append(matched, TopologyMatch{
				OldResult:   oldR,
				NewResult:   newR,
				OldTopology: oldTopo,
				NewTopology: newTopo,
				Similarity:  sim,
				ByName:      true,
			})
			matchedOld[name] = true
			matchedNew[name] = true
		}
	}

	// Phase 2: Collect unmatched functions
	var unmatchedOld []FingerprintResult
	var unmatchedNew []FingerprintResult

	for name, r := range oldByName {
		if !matchedOld[name] {
			unmatchedOld = append(unmatchedOld, r)
		}
	}
	for name, r := range newByName {
		if !matchedNew[name] {
			unmatchedNew = append(unmatchedNew, r)
		}
	}

	// Phase 3: Topology matching for unmatched functions
	if len(unmatchedOld) > 0 && len(unmatchedNew) > 0 {
		// Extract topologies
		oldTopos := make([]*FunctionTopology, len(unmatchedOld))
		newTopos := make([]*FunctionTopology, len(unmatchedNew))

		for i, r := range unmatchedOld {
			if fn := r.GetSSAFunction(); fn != nil {
				oldTopos[i] = ExtractTopology(fn)
			}
		}
		for i, r := range unmatchedNew {
			if fn := r.GetSSAFunction(); fn != nil {
				newTopos[i] = ExtractTopology(fn)
			}
		}

		// Build similarity matrix
		type candidate struct {
			oldIdx int
			newIdx int
			sim    float64
		}
		var candidates []candidate

		for i, oldTopo := range oldTopos {
			if oldTopo == nil {
				continue
			}
			for j, newTopo := range newTopos {
				if newTopo == nil {
					continue
				}
				sim := TopologySimilarity(oldTopo, newTopo)
				if sim >= threshold {
					candidates = append(candidates, candidate{i, j, sim})
				}
			}
		}

		// Greedy matching: sort by similarity descending, match greedily
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].sim > candidates[j].sim
		})

		usedOld := make(map[int]bool)
		usedNew := make(map[int]bool)

		for _, c := range candidates {
			if usedOld[c.oldIdx] || usedNew[c.newIdx] {
				continue
			}

			matched = append(matched, TopologyMatch{
				OldResult:   unmatchedOld[c.oldIdx],
				NewResult:   unmatchedNew[c.newIdx],
				OldTopology: oldTopos[c.oldIdx],
				NewTopology: newTopos[c.newIdx],
				Similarity:  c.sim,
				ByName:      false,
			})
			usedOld[c.oldIdx] = true
			usedNew[c.newIdx] = true
		}

		// Collect truly unmatched as added/removed
		for i, r := range unmatchedOld {
			if !usedOld[i] {
				removedFuncs = append(removedFuncs, r)
			}
		}
		for i, r := range unmatchedNew {
			if !usedNew[i] {
				addedFuncs = append(addedFuncs, r)
			}
		}
	} else {
		// No topology matching possible
		removedFuncs = unmatchedOld
		addedFuncs = unmatchedNew
	}

	return matched, addedFuncs, removedFuncs
}

// Extracts the function name without the full package path.
// For example:
//
//	"github.com/foo/bar.Method" -> "Method"
//	"github.com/foo/bar.(*Type).Method" -> "(*Type).Method"
func shortFuncName(fullName string) string {
	// Find the last occurrence of "/" to strip the full module path
	lastSlash := strings.LastIndex(fullName, "/")
	name := fullName
	if lastSlash >= 0 {
		name = fullName[lastSlash+1:]
	}

	// Now name is like "pkg.FuncName" or "pkg.(*Type).Method"
	// Find the first dot to strip the package name
	depth := 0
	for i, ch := range name {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case '.':
			if depth == 0 {
				return name[i+1:]
			}
		}
	}
	return name
}

// Generates a short structural fingerprint for display purposes.
// This is a human readable summary of the function's shape.
func TopologyFingerprint(t *FunctionTopology) string {
	if t == nil {
		return "nil"
	}

	// Collect sorted call signatures for determinism
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
