package semanticfw

import (
	"fmt"
	"go/constant"
	"go/types"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

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
	MaxStringLiteralLen = 4096      // 4KB limit per string
	MaxTotalStringBytes = 1024 * 64 // 64KB limit per function
)

// SetTopologyLimits adjusts the memory safeguards for string processing.
func SetTopologyLimits(maxLen, maxTotal int) {
	MaxStringLiteralLen = maxLen
	MaxTotalStringBytes = maxTotal
}

// ExtractTopology analyzes an SSA function and extracts its structural features.
func ExtractTopology(fn *ssa.Function) *FunctionTopology {
	if fn == nil || len(fn.Blocks) == 0 {
		return nil
	}

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

	loopInfo := DetectLoops(fn)
	t.LoopCount = countLoops(loopInfo.Loops)

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
						val := c.Value.ExactString()

						if len(val) > MaxStringLiteralLen {
							// UTF-8 safe truncation to avoid invalid strings
							val = val[:MaxStringLiteralLen]
							for !utf8.ValidString(val) {
								if len(val) == 0 {
									break
								}
								val = val[:len(val)-1]
							}
						}

						if currentStringBytes+len(val) <= MaxTotalStringBytes {
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

	totalSize := 0
	for _, s := range t.StringLiterals {
		if len(s) >= 2 && (s[0] == '"' || s[0] == '`') {
			totalSize += len(s) - 2
		} else {
			totalSize += len(s)
		}
	}

	dataAccumulator := make([]byte, 0, totalSize)
	for _, s := range t.StringLiterals {
		raw := strings.Trim(s, "\"`")
		dataAccumulator = append(dataAccumulator, []byte(raw)...)
	}

	if len(dataAccumulator) > 0 {
		t.EntropyScore = CalculateEntropy(dataAccumulator)
		t.EntropyProfile = CalculateEntropyProfile(dataAccumulator, t.StringLiterals)
	} else {
		t.EntropyScore = 0
		t.EntropyProfile = EntropyProfile{Classification: EntropyLow}
	}

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
		brBucket = int(math.Log2(float64(t.BranchCount)))
	}
	lBucket := t.LoopCount
	if lBucket > 5 {
		lBucket = 5
	}

	return fmt.Sprintf("B%dL%dBR%d", bBucket, lBucket, brBucket)
}

func normalizeTypeName(t types.Type) string {
	s := t.String()
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		s = s[idx+1:]
	}
	return s
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
		if fn := v.Fn.(*ssa.Function); fn != nil {
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
	if len(a) != len(b) {
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

type TopologyMatch struct {
	OldResult   FingerprintResult
	NewResult   FingerprintResult
	OldTopology *FunctionTopology
	NewTopology *FunctionTopology
	Similarity  float64
	ByName      bool
}

// MatchFunctionsByTopology correlates functions across versions using structural analysis.
func MatchFunctionsByTopology(oldResults, newResults []FingerprintResult, threshold float64) (
	matched []TopologyMatch,
	addedFuncs []FingerprintResult,
	removedFuncs []FingerprintResult,
) {
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

	matchedOld := make(map[string]bool)
	matchedNew := make(map[string]bool)

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

			sim := 1.0
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

	if len(unmatchedOld) > 0 && len(unmatchedNew) > 0 {
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

		// Use sort.SliceStable for deterministic ordering.
		// Sort descending by similarity.
		sort.SliceStable(candidates, func(i, j int) bool {
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
		removedFuncs = unmatchedOld
		addedFuncs = unmatchedNew
	}

	return matched, addedFuncs, removedFuncs
}

func shortFuncName(fullName string) string {
	lastSlash := strings.LastIndex(fullName, "/")
	name := fullName
	if lastSlash >= 0 {
		name = fullName[lastSlash+1:]
	}

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
