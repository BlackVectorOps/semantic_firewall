package detection_test

import (
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
)

func TestMatchSignature(t *testing.T) {
	t.Parallel()

	topo := &topology.FunctionTopology{
		BlockCount: 10, LoopCount: 1, EntropyScore: 5.0,
		CallSignatures: map[string]int{"net.Dial": 1},
	}
	topoHash := detection.GenerateTopologyHash(topo)

	tests := []struct {
		name      string
		sig       detection.Signature
		minConf   float64
		wantMatch bool
	}{
		{
			name: "Exact Match",
			sig: detection.Signature{
				TopologyHash: topoHash,
				EntropyScore: 5.0,
				IdentifyingFeatures: detection.IdentifyingFeatures{
					RequiredCalls: []string{"net.Dial"},
				},
			},
			minConf:   1.0,
			wantMatch: true,
		},
		{
			name: "Entropy Mismatch",
			sig: detection.Signature{
				TopologyHash:     topoHash,
				EntropyScore:     8.0, // Major diff
				EntropyTolerance: 0.1,
			},
			minConf:   0.8,
			wantMatch: false, // Should reduce confidence
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := detection.MatchSignature(topo, "test", tc.sig, 0.5)

			if tc.wantMatch {
				if res.Confidence < tc.minConf {
					t.Errorf("Confidence too low: %f < %f", res.Confidence, tc.minConf)
				}
			} else {
				if res.MatchDetails.EntropyMatch {
					t.Error("Expected entropy mismatch")
				}
			}
		})
	}
}
