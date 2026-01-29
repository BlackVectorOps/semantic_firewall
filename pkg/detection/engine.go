package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
)

// MatchSignature checks a function topology against a signature.
func MatchSignature(topo *topology.FunctionTopology, funcName string, sig Signature, entropyTolerance float64) ScanResult {
	result := ScanResult{
		SignatureID:     sig.ID,
		SignatureName:   sig.Name,
		Severity:        sig.Severity,
		MatchedFunction: funcName,
	}
	var scores []float64
	details := MatchDetails{}

	currentHash := GenerateTopologyHash(topo)
	if currentHash == sig.TopologyHash {
		details.TopologyMatch = true
		details.TopologySimilarity = 1.0
		scores = append(scores, 1.0)
	} else {
		similarity := ComputeTopologySimilarity(topo, sig)
		details.TopologySimilarity = similarity
		details.TopologyMatch = similarity > 0.8
		scores = append(scores, similarity)
	}

	sigTol := sig.EntropyTolerance
	if sigTol == 0 {
		sigTol = entropyTolerance
	}

	entropyDist := topology.EntropyDistance(topo.EntropyScore, sig.EntropyScore)
	details.EntropyDistance = entropyDist
	details.EntropyMatch = entropyDist <= sigTol
	if details.EntropyMatch {
		entropyScore := 1.0 - (entropyDist / sigTol)
		scores = append(scores, entropyScore)
	} else {
		scores = append(scores, 0.5)
	}

	if len(sig.IdentifyingFeatures.RequiredCalls) > 0 {
		callScore, matched, missing := MatchCalls(topo, sig.IdentifyingFeatures.RequiredCalls)
		details.CallsMatched = matched
		details.CallsMissing = missing
		if len(missing) > 0 {
			result.Confidence = 0.0
			result.MatchDetails = details
			return result
		}
		scores = append(scores, callScore)
	}

	if len(sig.IdentifyingFeatures.StringPatterns) > 0 {
		stringScore, matched := MatchStrings(topo, sig.IdentifyingFeatures.StringPatterns)
		details.StringsMatched = matched
		if stringScore > 0 {
			scores = append(scores, stringScore)
		}
	}

	if len(scores) > 0 {
		var total float64
		for _, sc := range scores {
			total += sc
		}
		result.Confidence = total / float64(len(scores))
	}
	result.MatchDetails = details
	return result
}

func ComputeTopologySimilarity(topo *topology.FunctionTopology, sig Signature) float64 {
	var scores []float64

	if sig.NodeCount > 0 && topo.BlockCount >= 0 {
		blockRatio := float64(topo.BlockCount) / float64(sig.NodeCount)
		if blockRatio > 1 {
			blockRatio = 1 / blockRatio
		}
		scores = append(scores, blockRatio)
	} else if sig.NodeCount > 0 && topo.BlockCount < 0 {
		scores = append(scores, 0.0)
	}

	if sig.LoopDepth > 0 && topo.LoopCount >= 0 {
		if topo.LoopCount == sig.LoopDepth {
			scores = append(scores, 1.0)
		} else if topo.LoopCount > 0 {
			loopRatio := float64(topo.LoopCount) / float64(sig.LoopDepth)
			if loopRatio > 1 {
				loopRatio = 1 / loopRatio
			}
			scores = append(scores, loopRatio)
		} else {
			scores = append(scores, 0.0)
		}
	} else if sig.LoopDepth > 0 && topo.LoopCount < 0 {
		scores = append(scores, 0.0)
	}

	if len(scores) == 0 {
		return 0.5
	}

	var total float64
	for _, s := range scores {
		total += s
	}
	return total / float64(len(scores))
}

func MatchCalls(topo *topology.FunctionTopology, required []string) (score float64, matched, missing []string) {
	for _, req := range required {
		found := false
		for call := range topo.CallSignatures {
			if strings.Contains(call, req) {
				found = true
				matched = append(matched, req)
				break
			}
		}
		if !found {
			missing = append(missing, req)
		}
	}
	if len(required) > 0 {
		score = float64(len(matched)) / float64(len(required))
	}
	return
}

func MatchStrings(topo *topology.FunctionTopology, patterns []string) (score float64, matched []string) {
	for _, pattern := range patterns {
		patLower := strings.ToLower(pattern)
		for _, lit := range topo.StringLiterals {
			if strings.Contains(strings.ToLower(lit), patLower) {
				matched = append(matched, pattern)
				break
			}
		}
	}
	if len(patterns) > 0 {
		score = float64(len(matched)) / float64(len(patterns))
	}
	return
}

func IndexFunction(topo *topology.FunctionTopology, name, description, severity, category string) Signature {
	topoHash := GenerateTopologyHash(topo)
	fuzzyHash := topology.GenerateFuzzyHash(topo)

	var requiredCalls []string
	for call := range topo.CallSignatures {
		requiredCalls = append(requiredCalls, call)
	}
	sort.Strings(requiredCalls)

	sig := Signature{
		Name:             name,
		Description:      description,
		Severity:         severity,
		Category:         category,
		TopologyHash:     topoHash,
		FuzzyHash:        fuzzyHash,
		EntropyScore:     topo.EntropyScore,
		EntropyTolerance: 0.5,
		NodeCount:        topo.BlockCount,
		LoopDepth:        topo.LoopCount,
		IdentifyingFeatures: IdentifyingFeatures{
			RequiredCalls:  requiredCalls,
			StringPatterns: ExtractStringPatterns(topo.StringLiterals),
			ControlFlow: &ControlFlowHints{
				HasInfiniteLoop:   topo.LoopCount > 0 && !topo.HasRange,
				HasReconnectLogic: HasReconnectLogic(topo),
			},
		},
	}
	return sig
}

func GenerateTopologyHash(topo *topology.FunctionTopology) string {
	var builder strings.Builder
	builder.WriteString("P")
	builder.WriteString(strconv.Itoa(topo.ParamCount))
	builder.WriteString("R")
	builder.WriteString(strconv.Itoa(topo.ReturnCount))
	builder.WriteString("B")
	builder.WriteString(strconv.Itoa(topo.BlockCount))
	builder.WriteString("I")
	builder.WriteString(strconv.Itoa(topo.InstrCount))
	builder.WriteString("L")
	builder.WriteString(strconv.Itoa(topo.LoopCount))
	builder.WriteString("BR")
	builder.WriteString(strconv.Itoa(topo.BranchCount))

	var calls []string
	for call, count := range topo.CallSignatures {
		var cb strings.Builder
		cb.WriteString(strconv.Itoa(len(call)))
		cb.WriteString(":")
		cb.WriteString(call)
		cb.WriteString(":")
		cb.WriteString(strconv.Itoa(count))
		calls = append(calls, cb.String())
	}
	sort.Strings(calls)
	builder.WriteString(strings.Join(calls, ";"))

	if topo.HasDefer {
		builder.WriteString("D")
	}
	if topo.HasGo {
		builder.WriteString("G")
	}
	if topo.HasSelect {
		builder.WriteString("S")
	}
	if topo.HasPanic {
		builder.WriteString("P")
	}

	hash := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(hash[:16])
}

func ExtractStringPatterns(literals []string) []string {
	patterns := make(map[string]bool)
	for _, lit := range literals {
		if len(lit) < 3 {
			continue
		}
		clean := strings.Trim(lit, "\"'`")
		if len(clean) >= 3 {
			patterns[clean] = true
		}
	}
	var result []string
	for p := range patterns {
		result = append(result, p)
	}
	sort.Strings(result)
	return result
}

func HasReconnectLogic(topo *topology.FunctionTopology) bool {
	hasNetDial := false
	hasSleep := false
	for call := range topo.CallSignatures {
		if strings.Contains(call, "net.Dial") {
			hasNetDial = true
		}
		if strings.Contains(call, "time.Sleep") {
			hasSleep = true
		}
	}
	return hasNetDial && hasSleep && topo.LoopCount > 0
}
