package topology

import (
	"go/constant"
	"math"

	"golang.org/x/tools/go/ssa"
)

// This file adds obfuscation-aware analysis on top of the structural topology
// extracted in topology.go. The original entropy path measured Shannon entropy
// of *concatenated string literals only*, which is blind to the techniques real
// Go obfuscators actually use:
//
//   - Payloads stored as []byte{0x..} / []int / string([]rune{...}) constant
//     pools, never as string constants (so they never entered StringLiterals).
//   - A single high-entropy blob averaged out by many low-entropy log strings.
//   - Control-flow flattening (one giant for{switch state}) and indirect/
//     reflective dispatch, which change *structure*, not string content.
//
// ObfuscationProfile measures all of these and produces a single 0..1 score
// plus discrete indicators that downstream scoring (engine.go) can weight.

// ObfuscationClass buckets the overall obfuscation score for quick triage.
type ObfuscationClass int

const (
	ObfuscationNone     ObfuscationClass = iota // < 0.25
	ObfuscationLow                              // 0.25 - 0.50
	ObfuscationModerate                         // 0.50 - 0.75
	ObfuscationHigh                             // >= 0.75
)

func (c ObfuscationClass) String() string {
	switch c {
	case ObfuscationNone:
		return "NONE"
	case ObfuscationLow:
		return "LOW"
	case ObfuscationModerate:
		return "MODERATE"
	case ObfuscationHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// ObfuscationProfile captures multi-signal obfuscation evidence for a function.
// All ratios are normalized 0..1 unless noted.
type ObfuscationProfile struct {
	// MaxWindowEntropy is the highest Shannon entropy (0..8) found in any
	// sliding window across the concatenated constant pool (strings + byte/int
	// arrays). Unlike a global mean, a single packed blob surfaces here even
	// when surrounded by benign data.
	MaxWindowEntropy float64

	// ConstPoolEntropy is the Shannon entropy (0..8) of the *non-string*
	// constant pool: integer and byte constants flowing into the function.
	// This is the signal the old path was completely missing.
	ConstPoolEntropy float64

	// ByteArrayPayloadBytes is the total number of bytes contributed by
	// small-integer constants (0..255) that look like an encoded payload.
	ByteArrayPayloadBytes int

	// IndirectCallRatio is dynamic+reflective calls over all calls. High values
	// indicate dispatch-table / reflection obfuscation that evades name-based
	// signatures.
	IndirectCallRatio float64

	// FlatteningScore estimates control-flow-flattening likelihood from the
	// dispatcher shape (one block with many predecessors and successors driving
	// a state variable). 0..1.
	FlatteningScore float64

	// DecoderLoopLikelihood is 0..1 evidence of an in-loop decode/XOR routine:
	// a loop body containing byte-wise arithmetic/bitwise ops over an indexed
	// buffer. This is the structural fingerprint of a string/payload decryptor.
	DecoderLoopLikelihood float64

	// Score is the aggregate 0..1 obfuscation score.
	Score float64

	// Class is the bucketed Score.
	Class ObfuscationClass

	// Indicators lists the human-readable signals that fired, for reporting.
	Indicators []string
}

// obfuscation tuning constants. Exported-adjacent but kept unexported; callers
// tune via the weights rather than these thresholds.
const (
	entropyWindowSize       = 256 // bytes per sliding window
	entropyWindowStride     = 128 // 50% overlap so a blob can't straddle a gap
	highWindowEntropyCutoff = 7.2 // >this in a window => likely packed/encrypted
	payloadByteRunMinLen    = 16  // min consecutive byte-range ints to call it a payload
	flatteningMinFanIn      = 4   // absolute predecessor floor before trusting the ratio
)

// AnalyzeObfuscation builds an ObfuscationProfile for an already-extracted
// topology. It re-walks the SSA function (held in t.fn) to gather the non-string
// constant pool, which ExtractTopology intentionally does not retain. If the
// underlying function is unavailable it falls back to string-only signals so the
// result is still meaningful for synthesized topologies in tests.
func AnalyzeObfuscation(t *FunctionTopology) ObfuscationProfile {
	var p ObfuscationProfile

	// 1. Gather the full constant byte pool: string literals AND numeric
	//    constants. Numeric constants in the 0..255 range are the bytes of a
	//    payload array; wider integers are length-delimited little-endian.
	pool := make([]byte, 0, 1024)
	for _, s := range t.StringLiterals {
		pool = append(pool, s...)
	}

	byteRun := 0
	maxByteRun := 0
	if t.fn != nil {
		// Walk every constant operand in program order. A "byte run" is a
		// maximal sequence of in-range (0..255) integer constants. SSA stores
		// each array element in its own instruction, so the run must persist
		// across instructions — it is only broken by a non-byte numeric value,
		// not by instruction boundaries.
		//
		// Structural operands must be excluded: array/slice *subscripts*
		// (IndexAddr/Index/Lookup .Index) and slice bounds (Slice .Low/.High/
		// .Max) are constants in 0..255 for any small array, but they are
		// addressing arithmetic, not payload data. Counting them double-counts
		// every []byte literal (each element store PLUS its IndexAddr subscript)
		// and injects a low-entropy 0,1,2,3… ramp that dilutes a genuine blob.
		for _, block := range t.fn.Blocks {
			for _, instr := range block.Instrs {
				skip := structuralConstOperands(instr)
				for _, op := range instr.Operands(nil) {
					if op == nil || *op == nil {
						continue
					}
					if skip != nil && skip[op] {
						continue
					}
					c, ok := (*op).(*ssa.Const)
					if !ok || c.Value == nil || c.Value.Kind() != constant.Int {
						continue
					}
					v, exact := constant.Int64Val(c.Value)
					if !exact {
						continue
					}
					if v >= 0 && v <= 255 {
						pool = append(pool, byte(v))
						byteRun++
						if byteRun > maxByteRun {
							maxByteRun = byteRun
						}
					} else {
						byteRun = 0
						// Fold wider ints into the pool little-endian so e.g.
						// uint32-packed payloads still register entropy.
						uv := uint64(v)
						for shift := 0; shift < 64 && uv != 0; shift += 8 {
							pool = append(pool, byte(uv))
							uv >>= 8
						}
					}
				}
			}
		}
	}
	p.ByteArrayPayloadBytes = maxByteRun

	// 2. Max-window entropy over the combined pool. This is the key fix for the
	//    "one blob averaged away by log strings" evasion.
	p.MaxWindowEntropy = maxWindowEntropy(pool)

	// 3. Entropy of the numeric-only pool (strings excluded), the signal the old
	//    path never computed.
	numericPool := pool
	if n := totalStringLen(t.StringLiterals); n > 0 && n <= len(pool) {
		numericPool = pool[n:]
	}
	if len(numericPool) > 0 {
		p.ConstPoolEntropy = CalculateEntropy(numericPool)
	}

	// 4. Indirect / reflective call ratio from the call signatures the topology
	//    already collected. extractCallSignature tags these "dynamic:" / "reflect:".
	totalCalls, indirectCalls := 0, 0
	for sig, n := range t.CallSignatures {
		totalCalls += n
		if isIndirectCallSig(sig) {
			indirectCalls += n
		}
	}
	if totalCalls > 0 {
		p.IndirectCallRatio = float64(indirectCalls) / float64(totalCalls)
	}

	// 5. Structural signals from SSA shape.
	if t.fn != nil {
		p.FlatteningScore = flatteningScore(t.fn)
		p.DecoderLoopLikelihood = decoderLoopLikelihood(t.fn)
	}

	// 6. Aggregate. Each contributing signal is normalized to 0..1 and combined
	//    with a weighted mean. Three correctness properties matter here:
	//
	//    (a) Applicability gating. A signal that *cannot fire in this function*
	//        (no const pool, no calls, no loops, too few blocks) contributes
	//        neither numerator nor denominator. Otherwise a permanently-zero
	//        inapplicable signal drags every score toward zero — e.g. a packed
	//        leaf function with no loops was being penalized by the decoder
	//        weight. Applicability is STRUCTURAL ("could this signal exist
	//        here"), never "did the signal score > 0": a function with calls
	//        that are all direct must still count its zero indirect-dispatch
	//        ratio against the obfuscation case.
	//
	//    (b) Dispositive floor. The weighted mean can let a weak corroborating
	//        signal DRAG DOWN a score that strong dispositive (data-entropy)
	//        evidence alone would justify. That is backwards — corroboration must
	//        only ever raise confidence. So the strongest dispositive signal sets
	//        a floor; the mean lifts above it but never sinks below.
	//
	//    (c) Lone-signal cap. Signals are not equal in evidentiary weight.
	//        Data-entropy signals (window entropy, const-pool entropy, byte-array
	//        run) are *dispositive* — a packed blob is a packed blob, and one is
	//        enough to call a function obfuscated. Structural signals (indirect
	//        dispatch, flattening, in-loop decoder) are *corroborating only*:
	//        each is individually consistent with idiomatic Go (a callback runner
	//        is indirect-only; a state machine looks flattened; a checksum loop
	//        looks like a decoder). So a function whose evidence is a single
	//        corroborating signal is capped below MODERATE; it takes either one
	//        dispositive signal, or two corroborating signals together, to reach
	//        the obfuscated bands. This kills the benign-higher-order-function
	//        false positive (func(f,g,h func()){f();g();h()}) without suppressing
	//        genuinely packed lone-signal payloads.
	hasFn := t.fn != nil
	loopApplicable := hasFn && len(naturalLoops(t.fn)) > 0
	flatApplicable := hasFn && len(t.fn.Blocks) >= 6

	type weighted struct {
		val         float64
		weight      float64
		applicable  bool
		dispositive bool
		label       string
	}
	signals := []weighted{
		{normCut(p.MaxWindowEntropy, 5.0, 8.0), 0.30, len(pool) > 0, true, "high-entropy-window"},
		{normCut(p.ConstPoolEntropy, 4.0, 8.0), 0.20, len(numericPool) > 0, true, "high-entropy-const-pool"},
		{normCut(float64(p.ByteArrayPayloadBytes), float64(payloadByteRunMinLen), 256), 0.15, p.ByteArrayPayloadBytes > 0, true, "byte-array-payload"},
		{p.IndirectCallRatio, 0.15, totalCalls > 0, false, "indirect-dispatch"},
		{p.FlatteningScore, 0.10, flatApplicable, false, "control-flow-flattening"},
		{p.DecoderLoopLikelihood, 0.10, loopApplicable, false, "in-loop-decoder"},
	}

	var score, wsum float64
	var strongestDispositive float64
	dispositiveFired, corroboratingFired := 0, 0
	for _, s := range signals {
		if !s.applicable {
			continue
		}
		score += s.val * s.weight
		wsum += s.weight
		if s.dispositive && s.val > strongestDispositive {
			strongestDispositive = s.val
		}
		if s.val >= 0.5 {
			p.Indicators = append(p.Indicators, s.label)
			if s.dispositive {
				dispositiveFired++
			} else {
				corroboratingFired++
			}
		}
	}
	if wsum > 0 {
		score /= wsum
	}

	// Dispositive floor (fixes corroboration-dilution). A weighted mean lets a
	// corroborating signal DRAG DOWN a score that strong dispositive evidence
	// alone would justify — observed concretely: payload+decoder scored LOWER
	// than the same payload alone, because the decoder's 0.5 pulled the mean
	// below the payload's own normalized value. That is backwards: corroboration
	// must only ever raise confidence. So the dispositive evidence sets a floor
	// equal to its own strength; the weighted mean (which folds in corroboration)
	// can lift above that floor but never sink below it.
	if strongestDispositive > score {
		score = strongestDispositive
	}

	// A single saturated high-entropy window is dispositive for packing even if
	// every other signal is quiet; floor the score accordingly.
	if p.MaxWindowEntropy >= highWindowEntropyCutoff {
		if hard := 0.75; score < hard {
			score = hard
		}
	}

	// Lone-signal cap (property (c) above). Insufficient evidence — no
	// dispositive signal and fewer than two corroborating signals — cannot reach
	// MODERATE, regardless of how high a single corroborating signal scored.
	if dispositiveFired == 0 && corroboratingFired < 2 {
		const loneSignalCap = 0.49
		if score > loneSignalCap {
			score = loneSignalCap
		}
	}

	p.Score = clamp01(score)
	p.Class = classifyObfuscation(p.Score)
	return p
}

func classifyObfuscation(score float64) ObfuscationClass {
	switch {
	case score < 0.25:
		return ObfuscationNone
	case score < 0.50:
		return ObfuscationLow
	case score < 0.75:
		return ObfuscationModerate
	default:
		return ObfuscationHigh
	}
}

// maxWindowEntropy returns the highest Shannon entropy over any sliding window
// of the data. For inputs smaller than one window it returns the whole-buffer
// entropy. This is what lets a small packed blob surface above surrounding
// low-entropy noise.
func maxWindowEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	if len(data) <= entropyWindowSize {
		return CalculateEntropy(data)
	}
	var max float64
	for start := 0; start < len(data); start += entropyWindowStride {
		end := start + entropyWindowSize
		if end > len(data) {
			end = len(data)
		}
		if e := CalculateEntropy(data[start:end]); e > max {
			max = e
		}
		if end == len(data) {
			break
		}
	}
	return max
}

// structuralConstOperands returns the set of operand slots on an instruction
// that carry addressing/structural constants (array subscripts, slice bounds)
// rather than payload data. These must be excluded from the entropy pool and
// byte-run count: a []byte{...} literal lowers each element to a Store whose
// value is the payload byte, but also an IndexAddr whose .Index is the
// subscript (0,1,2,…). Counting the subscript double-counts the array and
// injects a low-entropy ramp. Returns nil when the instruction has no
// structural operands (the common case), so callers can skip the map lookup.
func structuralConstOperands(instr ssa.Instruction) map[*ssa.Value]bool {
	switch i := instr.(type) {
	case *ssa.IndexAddr:
		return map[*ssa.Value]bool{&i.Index: true}
	case *ssa.Index:
		return map[*ssa.Value]bool{&i.Index: true}
	case *ssa.Lookup:
		return map[*ssa.Value]bool{&i.Index: true}
	case *ssa.Slice:
		m := make(map[*ssa.Value]bool, 3)
		if i.Low != nil {
			m[&i.Low] = true
		}
		if i.High != nil {
			m[&i.High] = true
		}
		if i.Max != nil {
			m[&i.Max] = true
		}
		if len(m) == 0 {
			return nil
		}
		return m
	}
	return nil
}

// isIndirectCallSig reports whether a call signature represents dynamic,
// reflective, or interface-dispatched calls — the shapes that defeat
// name-based required-call matching.
func isIndirectCallSig(sig string) bool {
	return hasPrefix(sig, "dynamic:") ||
		hasPrefix(sig, "reflect:") ||
		hasPrefix(sig, "invoke:") ||
		hasPrefix(sig, "go:dynamic:") ||
		hasPrefix(sig, "defer:dynamic:")
}

// flatteningScore estimates control-flow-flattening from the dispatcher's
// fan-IN concentration.
//
// Fan-out is the wrong axis: x/tools SSA lowers a switch into an if-comparison
// chain, so no basic block ever has more than two successors — a "succs >= 3"
// dispatcher shape is unreachable and never fires. The real signature of a
// flattened state machine is the opposite: every case block jumps back to one
// state-check header, so that header's predecessor count approaches the number
// of cases. Normal control flow distributes its predecessors, keeping the
// maximum fan-in low relative to the block count.
func flatteningScore(fn *ssa.Function) float64 {
	if len(fn.Blocks) < 6 {
		return 0
	}
	maxPred := 0
	for _, b := range fn.Blocks {
		if len(b.Preds) > maxPred {
			maxPred = len(b.Preds)
		}
	}
	// Absolute fan-in floor. The ratio alone is unstable for small functions: a
	// normal 6-block `for range` with a continue+break has a 3-pred header →
	// ratio 0.5, a false positive. A genuine flattening dispatcher routes many
	// case blocks back to one header, so its absolute fan-in is high regardless
	// of size; require that before trusting the ratio.
	if maxPred < flatteningMinFanIn {
		return 0
	}
	// Ratio, not raw count, so it scales with function size rather than firing
	// on every large function. Knee at 25% fan-in, saturating at 75%.
	ratio := float64(maxPred) / float64(len(fn.Blocks))
	return clamp01((ratio - 0.25) / 0.5)
}

// decoderLoopLikelihood looks for the structural fingerprint of an in-loop
// byte decoder: a natural loop whose body performs bitwise/arithmetic BinOps
// (XOR/ADD/SUB/SHL/SHR/AND/OR) over an indexed buffer access. SSA splits a loop
// body across several blocks (header, body, latch), so evidence is gathered
// over the whole set of blocks belonging to each loop rather than a single
// block.
func decoderLoopLikelihood(fn *ssa.Function) float64 {
	loops := naturalLoops(fn)
	if len(loops) == 0 {
		return 0
	}
	var best float64
	for _, blocks := range loops {
		hasIndexedAccess := false
		bitwiseOps := 0
		for b := range blocks {
			for _, instr := range b.Instrs {
				switch i := instr.(type) {
				case *ssa.IndexAddr, *ssa.Index, *ssa.Lookup:
					hasIndexedAccess = true
				case *ssa.BinOp:
					switch i.Op.String() {
					case "^", "&", "|", "<<", ">>", "+", "-":
						bitwiseOps++
					}
				}
			}
		}
		if hasIndexedAccess && bitwiseOps > 0 {
			score := clamp01(float64(bitwiseOps) / 4.0)
			if score > best {
				best = score
			}
		}
	}
	return best
}

// naturalLoops returns, for each back edge, the set of blocks in that loop. A
// back edge is an edge b->h where h's index is <= b's index (forward-numbered
// CFG). The loop body is everything that can reach b without going through h,
// computed by a reverse walk from the latch bounded by the header. This is a
// standard natural-loop body computation and is independent of the loop package
// to avoid an import cycle.
func naturalLoops(fn *ssa.Function) []map[*ssa.BasicBlock]bool {
	var loops []map[*ssa.BasicBlock]bool
	for _, b := range fn.Blocks {
		for _, h := range b.Succs {
			if h.Index > b.Index {
				continue // not a back edge
			}
			body := map[*ssa.BasicBlock]bool{h: true, b: true}
			stack := []*ssa.BasicBlock{b}
			for len(stack) > 0 {
				n := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if n == h {
					continue
				}
				for _, pr := range n.Preds {
					if !body[pr] {
						body[pr] = true
						stack = append(stack, pr)
					}
				}
			}
			loops = append(loops, body)
		}
	}
	return loops
}

// --- small numeric helpers (kept local to avoid touching topology.go) ---

func normCut(v, lo, hi float64) float64 {
	if hi <= lo {
		return 0
	}
	if v <= lo {
		return 0
	}
	if v >= hi {
		return 1
	}
	return (v - lo) / (hi - lo)
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func totalStringLen(ss []string) int {
	n := 0
	for _, s := range ss {
		n += len(s)
	}
	return n
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
