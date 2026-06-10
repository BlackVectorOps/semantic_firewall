package detection_test

import (
	"math"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/detection"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 0.005 }

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// --- 3a: required-call gate relaxation for indirect dispatch ---

func TestMatchSignature_Gate_DirectDispatch_HardZeros(t *testing.T) {
	t.Parallel()
	topo := &topology.FunctionTopology{
		BlockCount:     10,
		CallSignatures: map[string]int{"net.Dial": 1},
		// direct dispatch, not obfuscated -> a missing required call is meaningful
		Obfuscation: topology.ObfuscationProfile{IndirectCallRatio: 0, Class: topology.ObfuscationNone},
	}
	sig := detection.Signature{
		IdentifyingFeatures: detection.IdentifyingFeatures{RequiredCalls: []string{"missing.Call"}},
	}
	res := detection.MatchSignature(topo, "f", sig, 0.5)
	if res.Confidence != 0 {
		t.Errorf("direct dispatch with missing required call should hard-zero, got %.3f", res.Confidence)
	}
	if !contains(res.MatchDetails.CallsMissing, "missing.Call") {
		t.Errorf("CallsMissing=%v", res.MatchDetails.CallsMissing)
	}
}

func TestMatchSignature_Gate_IndirectDispatch_NotZeroed(t *testing.T) {
	t.Parallel()
	topo := &topology.FunctionTopology{
		BlockCount:     10,
		CallSignatures: map[string]int{"dynamic:func()": 1},
		Obfuscation:    topology.ObfuscationProfile{IndirectCallRatio: 0.8, Class: topology.ObfuscationHigh},
	}
	sig := detection.Signature{
		NodeCount:           10, // topo similarity contributes > 0
		IdentifyingFeatures: detection.IdentifyingFeatures{RequiredCalls: []string{"missing.Call"}},
	}
	res := detection.MatchSignature(topo, "f", sig, 0.5)
	if res.Confidence <= 0 {
		t.Errorf("indirect dispatch should NOT be hard-zeroed by a missing call, got %.3f", res.Confidence)
	}
}

func TestMatchSignature_Gate_Boundaries(t *testing.T) {
	t.Parallel()
	sig := detection.Signature{
		NodeCount:           10,
		IdentifyingFeatures: detection.IdentifyingFeatures{RequiredCalls: []string{"missing.Call"}},
	}
	cases := []struct {
		name string
		obf  topology.ObfuscationProfile
	}{
		// ratio exactly 0.5 is NOT < 0.5, so the gate does not zero.
		{"ratio at 0.5 relaxes", topology.ObfuscationProfile{IndirectCallRatio: 0.5, Class: topology.ObfuscationNone}},
		// Class exactly Moderate is NOT < Moderate, so the gate does not zero.
		{"class at Moderate relaxes", topology.ObfuscationProfile{IndirectCallRatio: 0, Class: topology.ObfuscationModerate}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			topo := &topology.FunctionTopology{BlockCount: 10, CallSignatures: map[string]int{"x": 1}, Obfuscation: tc.obf}
			res := detection.MatchSignature(topo, "f", sig, 0.5)
			if res.Confidence <= 0 {
				t.Errorf("boundary case should relax (not zero), got %.3f", res.Confidence)
			}
		})
	}
}

// --- 3b: obfuscation confidence floor ---

// floorTopo builds a topology whose aggregate confidence (topoSim + entropy
// mismatch) lands at a target, so the floor's boundaries can be pinned.
// With sig.NodeCount=100 and entropy forced to mismatch (0.5), confidence is
// (blockCount/100 + 0.5) / 2.
func floorTopo(blockCount int, obfScore float64) *topology.FunctionTopology {
	return &topology.FunctionTopology{
		BlockCount:   blockCount,
		EntropyScore: 0,
		Obfuscation:  topology.ObfuscationProfile{Score: obfScore, Class: topology.ObfuscationHigh},
	}
}

func floorSig() detection.Signature {
	return detection.Signature{NodeCount: 100, EntropyScore: 8.0, EntropyTolerance: 0.1}
}

func TestMatchSignature_Floor_DormantBelowPartialMatch(t *testing.T) {
	t.Parallel()
	// blockCount 20 -> topoSim 0.2 -> confidence (0.2+0.5)/2 = 0.35 < 0.4.
	// Even with obf 0.99, the floor must NOT lift a poor match (side door closed).
	topo := floorTopo(20, 0.99)
	res := detection.MatchSignature(topo, "f", floorSig(), 0.5)
	if !approx(res.Confidence, 0.35) {
		t.Errorf("confidence=%.4f want ~0.35 (floor must not lift a <0.4 match)", res.Confidence)
	}
}

func TestMatchSignature_Floor_ActiveOnHighObf(t *testing.T) {
	t.Parallel()
	// blockCount 32 -> topoSim 0.32 -> confidence 0.41 >= 0.4.
	// obf 0.95 -> floor 0.475 > 0.41 -> confidence raised to 0.475.
	topo := floorTopo(32, 0.95)
	res := detection.MatchSignature(topo, "f", floorSig(), 0.5)
	if !approx(res.Confidence, 0.475) {
		t.Errorf("confidence=%.4f want ~0.475 (HIGH obf should floor an already-partial match)", res.Confidence)
	}
}

func TestMatchSignature_Floor_DormantOnModerateObf(t *testing.T) {
	t.Parallel()
	// Same 0.41 prior, but obf 0.8 -> floor 0.40 < 0.41 -> no change.
	// Confirms only obf > 0.8 can move the needle.
	topo := floorTopo(32, 0.8)
	res := detection.MatchSignature(topo, "f", floorSig(), 0.5)
	if !approx(res.Confidence, 0.41) {
		t.Errorf("confidence=%.4f want ~0.41 (obf 0.8 must not lift it)", res.Confidence)
	}
}

// --- visibility fields populated even on the hard-gate early return ---

func TestMatchSignature_VisibilityOnEarlyReturn(t *testing.T) {
	t.Parallel()
	topo := &topology.FunctionTopology{
		BlockCount:     10,
		CallSignatures: map[string]int{"net.Dial": 1},
		Obfuscation: topology.ObfuscationProfile{
			Score: 0.3, Class: topology.ObfuscationLow, IndirectCallRatio: 0.1,
			Indicators: []string{"in-loop-decoder"},
		},
	}
	sig := detection.Signature{
		IdentifyingFeatures: detection.IdentifyingFeatures{RequiredCalls: []string{"missing.Call"}},
	}
	res := detection.MatchSignature(topo, "f", sig, 0.5)
	if res.Confidence != 0 {
		t.Fatalf("expected hard-zero, got %.3f", res.Confidence)
	}
	// The early return must still carry the obfuscation evidence for triage.
	if !approx(res.MatchDetails.ObfuscationScore, 0.3) {
		t.Errorf("ObfuscationScore=%.3f want 0.3 on early return", res.MatchDetails.ObfuscationScore)
	}
	if res.MatchDetails.ObfuscationClass != "LOW" {
		t.Errorf("ObfuscationClass=%q want LOW", res.MatchDetails.ObfuscationClass)
	}
	if !contains(res.MatchDetails.ObfuscationSignals, "in-loop-decoder") {
		t.Errorf("ObfuscationSignals=%v", res.MatchDetails.ObfuscationSignals)
	}
}

// --- IndexFunction records the score onto the signature ---

func TestIndexFunction_RecordsObfuscationScore(t *testing.T) {
	t.Parallel()
	topo := &topology.FunctionTopology{
		BlockCount:     5,
		CallSignatures: map[string]int{},
		Obfuscation:    topology.ObfuscationProfile{Score: 0.7, Class: topology.ObfuscationModerate},
	}
	sig := detection.IndexFunction(topo, "name", "desc", "HIGH", "cat")
	if !approx(sig.ObfuscationScore, 0.7) {
		t.Errorf("sig.ObfuscationScore=%.3f want 0.7", sig.ObfuscationScore)
	}
}
