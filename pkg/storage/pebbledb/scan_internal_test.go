package pebbledb

import (
	"math"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/detection"
	"github.com/cockroachdb/pebble"
)

// storeWithSignature returns a store holding sig, whose topology hash is
// topo's, indexed with a legacy (unpacked) entry when legacy is set.
func storeWithSignature(t *testing.T, topo *topology.FunctionTopology, sig detection.Signature, legacy bool) *PebbleScanner {
	t.Helper()
	s, err := NewPebbleScanner(t.TempDir(), DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	sig.TopologyHash = detection.GenerateTopologyHash(topo)
	if err := s.AddSignature(&sig); err != nil {
		t.Fatal(err)
	}
	if legacy {
		// A legacy index value is the bare ID, with no entropy to gate on.
		if err := s.db.Set(buildTopoIndexKey(sig.TopologyHash, sig.ID), []byte(sig.ID), pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func scanTopo() *topology.FunctionTopology {
	return &topology.FunctionTopology{ParamCount: 1, BlockCount: 3, EntropyScore: 4}
}

// A legacy index entry carries no entropy, so the gate is applied to the
// loaded signature instead.
func TestScan_LegacyEntryGatedAfterLoad(t *testing.T) {
	topo := scanTopo()
	for _, tc := range []struct {
		entropy float64
		want    bool
	}{{4.2, true}, {9, false}} {
		s := storeWithSignature(t, topo, detection.Signature{ID: "L", EntropyScore: tc.entropy, EntropyTolerance: 0.5}, true)
		got, err := s.ScanTopologyExact(topo, "f")
		if err != nil {
			t.Fatal(err)
		}
		if (got != nil) != tc.want {
			t.Errorf("entropy %v: match %+v; want match %v", tc.entropy, got, tc.want)
		}
	}
}

// A signature whose entropy tolerance is NaN is not excluded by the entropy
// gate, so it scores as it does in the JSON store.
func TestScan_NaNToleranceNotGated(t *testing.T) {
	topo := scanTopo()
	s := storeWithSignature(t, topo, detection.Signature{ID: "N", EntropyScore: 4, EntropyTolerance: math.NaN()}, false)
	got, err := s.ScanTopology(topo, "f")
	if err != nil {
		t.Fatal(err)
	}
	want := detection.MatchSignature(topo, "f", detection.Signature{ID: "N", TopologyHash: detection.GenerateTopologyHash(topo), EntropyScore: 4, EntropyTolerance: math.NaN()}, 0.5)
	if len(got) != 1 || got[0].Confidence != want.Confidence {
		t.Errorf("ScanTopology = %+v; want the JSON store's confidence %v", got, want.Confidence)
	}
}
