package topology

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/loop"
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

	// CallTargets counts every function called or referenced as a value,
	// keyed by import-path-qualified name ("os/exec.Command"). Package
	// initializers are excluded. Capabilities maps the subset of those keys
	// that are security-sensitive to their capability class (CapExec, ...).
	CallTargets  map[string]int
	Capabilities map[string]string

	// Checks holds the verifications this function performs: calls to a
	// verification primitive (MAC and signature checks, certificate
	// verification, password hash comparison; see IsVerificationCall), to a
	// helper that reaches one, and to a function or interface method named
	// like a verification whose result decides a branch (see
	// collectCheckHelpers). Losing one is how a guard gets deleted.
	Checks map[string]bool

	// CapabilityGuards maps each Capabilities key to the fewest conditional
	// branches, loop conditions excluded, that any of its references in this
	// function is control-dependent on. 0 means some reference runs
	// unconditionally. Nil when the function has more than 2000 blocks.
	CapabilityGuards map[string]int

	// WeakSettings and SecureSettings hold constant stores to security
	// configuration fields, written "crypto/tls.Config.InsecureSkipVerify=true".
	// A weak setting weakens security on its own; a secure setting weakens it
	// by its removal. See collectSecuritySettings.
	WeakSettings   map[string]bool
	SecureSettings map[string]bool

	// ErrorExits counts the two-way branches with exactly one side that ends
	// the function with a failure: a non-nil error return, a panic, a call
	// that never returns, or an HTTP 4xx/5xx response.
	ErrorExits int

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

	// HasInfiniteLoop reports a `for` statement without a condition
	// (`for { ... }`) in the function's own body. Such a loop only ends
	// through break, return, goto or panic.
	HasInfiniteLoop bool

	// Operator profile
	BinOpCounts map[string]int
	UnOpCounts  map[string]int

	// String literal hashes (for behavioral matching)
	StringLiterals []string

	// Entropy analysis for obfuscation detection
	EntropyScore   float64
	EntropyProfile EntropyProfile

	// Multi-signal obfuscation analysis: sliding-window and const-pool entropy,
	// indirect/reflective dispatch ratio, control-flow flattening, and in-loop
	// decoder fingerprints. Captures payloads the string-only entropy path misses.
	Obfuscation ObfuscationProfile

	// The underlying function (internal use)
	fn *ssa.Function
}

var (
	// MaxStringLiteralLen and MaxTotalStringBytes bound the string
	// literals one topology keeps, so a function with huge literals cannot
	// exhaust memory. Set them with SetTopologyLimits; configMu guards them.
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
		CallTargets:    make(map[string]int),
		Capabilities:   make(map[string]string),
		Checks:         make(map[string]bool),
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

	// Also count the function's loop statements: a loop whose body always
	// exits (for { return }) has no back edge in the CFG.
	if fn.Syntax() != nil {
		astLoops := 0
		root := fn.Syntax()
		ast.Inspect(root, func(n ast.Node) bool {
			// A closure is its own SSA function; its loops are not this
			// function's.
			if n != root {
				if _, isClosure := n.(*ast.FuncLit); isClosure {
					return false
				}
			}

			switch s := n.(type) {
			case *ast.ForStmt:
				astLoops++
				if s.Cond == nil {
					t.HasInfiniteLoop = true
				}
			case *ast.RangeStmt:
				astLoops++
			}
			return true
		})

		// Take the higher count: an attacker gains nothing by hiding
		// loops from one of the two views.
		if astLoops > t.LoopCount {
			t.LoopCount = astLoops
		}
	}

	currentStringBytes := 0
	edgeCount := 0
	callsRecover := false
	var ops []*ssa.Value

	for _, block := range fn.Blocks {
		t.InstrCount += len(block.Instrs)
		edgeCount += len(block.Succs)

		for _, instr := range block.Instrs {
			// Track exact instruction types for granular similarity; the
			// key is what %T prints.
			t.InstrCounts[reflect.TypeOf(instr).String()]++

			switch i := instr.(type) {
			case *ssa.If:
				t.BranchCount++
			case *ssa.Phi:
				t.PhiCount++
			case *ssa.Call:
				sig := extractCallSignature(i)
				t.CallSignatures[sig]++
				if b, ok := i.Call.Value.(*ssa.Builtin); ok && b.Name() == "recover" {
					callsRecover = true
				}
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

			ops = instr.Operands(ops[:0])
			for _, op := range ops {
				if op == nil || *op == nil {
					continue
				}
				if c, ok := (*op).(*ssa.Const); ok && c.Value != nil {
					if c.Value.Kind() == constant.String {
						val := constant.StringVal(c.Value)

						if len(val) > maxStrLen {
							val = val[:maxStrLen]
						}

						val = truncateToValidUTF8(val)

						if currentStringBytes+len(val) <= maxTotalBytes {
							t.StringLiterals = append(t.StringLiterals, val)
							currentStringBytes += len(val)
						}
					}
				}
			}
		}
	}

	collectCallTargets(fn, t)
	collectCheckHelpers(fn, t)
	collectSecuritySettings(fn, t)
	nr := noReturns{}
	collectCapabilityGuards(fn, t, loopInfo, nr)
	t.ErrorExits = countErrorExits(fn, nr)

	// Calculate Cyclomatic Complexity: M = E - N + 2P
	// For a single function, P (connected components) is usually 1.
	t.CyclomaticComplexity = edgeCount - t.BlockCount + 2

	t.HasRecover = t.HasDefer && callsRecover

	sort.Strings(t.StringLiterals)

	dataAccumulator := flattenStringLiterals(t.StringLiterals)

	if len(dataAccumulator) > 0 {
		t.EntropyScore = CalculateEntropy(dataAccumulator)
		t.EntropyProfile = CalculateEntropyProfile(dataAccumulator, t.StringLiterals)
	} else {
		t.EntropyScore = 0
		t.EntropyProfile = EntropyProfile{Classification: EntropyLow}
	}

	// Multi-signal obfuscation analysis. Reads t.fn, t.StringLiterals and
	// t.CallSignatures — all populated by this point.
	t.Obfuscation = AnalyzeObfuscation(t)

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
		// Differentiate between 0 branches (linear) and 1 branch (single if).
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

// normalizeTypeName renders t with every package path's directories
// removed ("map[string]*net/http.Request" -> "map[string]*http.Request");
// a regexp keeps the type modifiers before a path, which cutting at the
// last slash would drop.
func normalizeTypeName(t types.Type) string {
	s := t.String()
	if !strings.Contains(s, "/") {
		return s
	}
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
		if sig := extractClosureSignature(v); sig != "" {
			return sig
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
	// In invoke mode (go w.Do()), Value is the receiver.
	if g.Call.IsInvoke() {
		recvType := g.Call.Value.Type()
		return fmt.Sprintf("invoke:%s.%s", normalizeTypeName(recvType), g.Call.Method.Name())
	}

	switch v := g.Call.Value.(type) {
	case *ssa.Function:
		return extractFunctionSig(v)
	case *ssa.MakeClosure:
		if sig := extractClosureSignature(v); sig != "" {
			return sig
		}
	}
	// Fallback for dynamic function pointers
	if g.Call.Value != nil {
		return fmt.Sprintf("dynamic:%s", normalizeTypeName(g.Call.Value.Type()))
	}
	return "unknown"
}

func extractDeferSignature(d *ssa.Defer) string {
	// In invoke mode (defer w.Close()), Value is the receiver.
	if d.Call.IsInvoke() {
		recvType := d.Call.Value.Type()
		return fmt.Sprintf("invoke:%s.%s", normalizeTypeName(recvType), d.Call.Method.Name())
	}

	switch v := d.Call.Value.(type) {
	case *ssa.Function:
		return extractFunctionSig(v)
	case *ssa.MakeClosure:
		if sig := extractClosureSignature(v); sig != "" {
			return sig
		}
	}
	if d.Call.Value != nil {
		return fmt.Sprintf("dynamic:%s", normalizeTypeName(d.Call.Value.Type()))
	}
	return "unknown"
}

func extractClosureSignature(v *ssa.MakeClosure) string {
	if fn, ok := v.Fn.(*ssa.Function); ok && fn != nil {
		return fmt.Sprintf("closure:%s", fn.Signature.String())
	}
	return ""
}

func extractFunctionSig(fn *ssa.Function) string {
	// A closure without free variables is called directly, as a plain
	// Function; name it by signature, as a MakeClosure is, so the name does
	// not depend on its creation number.
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
	// The Dice coefficient of the position-wise matches, so lists that
	// differ only in length (one extra parameter) still score as similar.
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
		totalSize += len(s)
	}

	dataAccumulator := make([]byte, 0, totalSize)
	for _, s := range literals {
		dataAccumulator = append(dataAccumulator, s...)
	}
	return dataAccumulator
}

// truncateToValidUTF8 returns the longest valid UTF-8 prefix of s.
func truncateToValidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}

	validLen := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			break // Stop at first invalid byte
		}
		validLen += size
		i += size
	}
	return s[:validLen]
}
