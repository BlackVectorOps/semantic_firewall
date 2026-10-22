package pebbledb_test

import (
	"math"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/storage/pebbledb"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/testutil"
)

const scanSrc = `package main

import (
	"net"
	"os/exec"
	"time"
)

func beacon(addr string) {
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
		}
		time.Sleep(time.Second)
	}
}

func run(cmd string) error {
	return exec.Command(cmd, "-c", "id").Run()
}

func sum(xs []int) int {
	s := 0
	for _, x := range xs {
		s += x
	}
	return s
}

func main() {}
`

// The Pebble store returns, for each indexed function, its own signature at
// confidence 1 from both scans, and every match it reports is one the JSON
// store, which scores every signature, reports with the same confidence.
func TestPebbleScanner_ScanMatchesJSONStore(t *testing.T) {
	names := []string{"beacon", "run", "sum"}
	topos := make(map[string]*topology.FunctionTopology)
	for _, name := range names {
		topos[name] = topology.ExtractTopology(testutil.CompileAndGetFunction(t, scanSrc, name))
	}

	ps, err := pebbledb.NewPebbleScanner(t.TempDir(), pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	js := jsondb.NewScanner()

	for _, name := range names {
		sig := detection.IndexFunction(topos[name], "sig_"+name, "", "HIGH", "malware")
		sig.ID = "SIG-" + name
		if err := ps.AddSignature(&sig); err != nil {
			t.Fatal(err)
		}
		if err := js.AddSignature(&sig); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range names {
		got, err := ps.ScanTopology(topos[name], name)
		if err != nil {
			t.Fatalf("ScanTopology(%s): %v", name, err)
		}
		want, err := js.ScanTopology(topos[name], name)
		if err != nil {
			t.Fatal(err)
		}
		jsonConf := make(map[string]float64)
		for _, r := range want {
			jsonConf[r.SignatureID] = r.Confidence
		}
		self := false
		ids := make(map[string]bool)
		for _, r := range got {
			// A signature is in both the topology and the fuzzy bucket.
			if ids[r.SignatureID] {
				t.Errorf("%s: %s reported twice", name, r.SignatureID)
			}
			ids[r.SignatureID] = true
			if c, ok := jsonConf[r.SignatureID]; !ok || c != r.Confidence {
				t.Errorf("%s: pebble match %s at %v; JSON store has %v (present %v)", name, r.SignatureID, r.Confidence, c, ok)
			}
			self = self || (r.SignatureID == "SIG-"+name && r.Confidence == 1)
		}
		if !self {
			t.Errorf("%s: ScanTopology = %+v; want its own signature at confidence 1", name, got)
		}

		exact, err := ps.ScanTopologyExact(topos[name], name)
		if err != nil {
			t.Fatal(err)
		}
		if exact == nil || exact.SignatureID != "SIG-"+name || exact.Confidence != 1 {
			t.Errorf("%s: ScanTopologyExact = %+v; want its own signature at confidence 1", name, exact)
		}
	}
}

// A candidate whose indexed entropy is outside its tolerance is rejected.
func TestPebbleScanner_ScanRejectsDistantEntropy(t *testing.T) {
	topo := topology.ExtractTopology(testutil.CompileAndGetFunction(t, scanSrc, "run"))

	ps, err := pebbledb.NewPebbleScanner(t.TempDir(), pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	sig := detection.IndexFunction(topo, "far", "", "HIGH", "malware")
	sig.ID = "SIG-FAR"
	sig.EntropyScore = topo.EntropyScore + 2*sig.EntropyTolerance
	if err := ps.AddSignature(&sig); err != nil {
		t.Fatal(err)
	}

	if got, err := ps.ScanTopology(topo, "run"); err != nil || len(got) != 0 {
		t.Errorf("ScanTopology = %+v, %v; want no matches", got, err)
	}
	if got, err := ps.ScanTopologyExact(topo, "run"); err != nil || got != nil {
		t.Errorf("ScanTopologyExact = %+v, %v; want no match", got, err)
	}
}

// An invalid threshold is refused: NaN fails every comparison and would
// suppress every alert.
func TestNewPebbleScanner_RefusesInvalidThreshold(t *testing.T) {
	for _, th := range []float64{math.NaN(), math.Inf(1), -0.1, 1.5} {
		opts := pebbledb.DefaultPebbleScannerOptions()
		opts.MatchThreshold = th
		if ps, err := pebbledb.NewPebbleScanner(t.TempDir(), opts); err == nil {
			ps.Close()
			t.Errorf("threshold %v accepted", th)
		}
	}
}

// SetMatchThreshold takes 0 and refuses what isn't in [0, 1]; the
// deprecated SetThreshold ignores those, keeping the previous threshold.
func TestPebbleScanner_SetMatchThreshold(t *testing.T) {
	topo := topology.ExtractTopology(testutil.CompileAndGetFunction(t, scanSrc, "beacon"))
	ps, err := pebbledb.NewPebbleScanner(t.TempDir(), pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	sig := detection.IndexFunction(topo, "sig_beacon", "", "HIGH", "malware")
	if err := ps.AddSignature(&sig); err != nil {
		t.Fatal(err)
	}
	// Same shape, required calls gone: a candidate far below 0.75.
	near := *topo
	near.CallSignatures = map[string]int{}
	if c := detection.NewMatcher(&near, "beacon").Match(sig, 0.5).Confidence; c >= 0.75 {
		t.Fatalf("near-match confidence %v; the test needs one below 0.75", c)
	}
	scan := func() int {
		res, err := ps.ScanTopology(&near, "beacon")
		if err != nil {
			t.Fatal(err)
		}
		return len(res)
	}
	if n := scan(); n != 0 {
		t.Fatalf("%d results at the default threshold; want 0", n)
	}
	if err := ps.SetMatchThreshold(0); err != nil {
		t.Fatal(err)
	}
	if n := scan(); n != 1 {
		t.Fatalf("%d results at threshold 0; want 1", n)
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1), -0.1, 1.5} {
		if err := ps.SetMatchThreshold(bad); err == nil {
			t.Errorf("SetMatchThreshold(%v) accepted", bad)
		}
		ps.SetThreshold(bad)
		if n := scan(); n != 1 {
			t.Errorf("after threshold %v: %d results; want the threshold of 0 kept", bad, n)
		}
	}
}
