package api_test

import (
	"reflect"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// One diff with every status: the summary's counts and percentages, each
// function's status, score and evidence, and the topology matches.
func TestDiff_Summary(t *testing.T) {
	out := diffSources(t, `package p

import (
	"crypto/hmac"
	"errors"
)

func Keep(a, b int) int { return a + b }

func Mod(x int) int { return x * 2 }

func OldName(s []int) int {
	n := 0
	for _, v := range s {
		n += v
	}
	return n
}

func Gone(mac, want []byte) error {
	if !hmac.Equal(mac, want) {
		return errors.New("bad mac")
	}
	return nil
}

func GoneHarmless(x int) int { return x + 1 }
`, `package p

import "net"

func Keep(a, b int) int { return a + b }

func Mod(x int) int { return x * 3 }

func NewName(s []int) int {
	n := 0
	for _, v := range s {
		n += v
	}
	return n
}

func Added(addr string) error {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}
`)
	got := map[string]models.FunctionDiff{}
	for _, f := range out.Functions {
		got[f.Function] = f
		t.Logf("%-20s %-9s risk=%-2d %s", f.Function, f.Status, f.RiskScore, f.TopologyDelta)
	}
	for name, want := range map[string]struct {
		status string
		risk   int
	}{
		"Keep":              {models.StatusPreserved, 0},
		"Mod":               {models.StatusModified, 0},
		"OldName → NewName": {models.StatusRenamed, 0},
		"Gone":              {models.StatusRemoved, models.RiskScoreHigh},
		"GoneHarmless":      {models.StatusRemoved, 0}, // removing a function without a check is neutral
		"Added":             {models.StatusAdded, models.BaseRiskAddedFunc + 1 + 20},
		"init":              {models.StatusModified, 0},
	} {
		if f, ok := got[name]; !ok || f.Status != want.status || f.RiskScore != want.risk {
			t.Errorf("%s: %+v; want %s, risk %d", name, f, want.status, want.risk)
		}
	}
	if mod := got["Mod"]; len(mod.AddedOps) == 0 || len(mod.RemovedOps) == 0 {
		t.Errorf("Mod: added ops %q, removed ops %q; want the Zipper's evidence of the changed constant", mod.AddedOps, mod.RemovedOps)
	}
	pct := func(n float64) float64 { return n / 7 * 100 } // in float64, as the summary computes it
	want := models.DiffSummary{
		TotalFunctions: 7, Preserved: 1, Modified: 3, Added: 1, Removed: 2,
		SemanticMatchPct: pct(1), TopologyMatchedPct: pct(4), RenamedFunctions: 1, HighRiskChanges: 2,
	}
	if out.Summary != want {
		t.Errorf("summary %+v; want %+v", out.Summary, want)
	}
	if len(out.TopologyMatches) != 4 {
		t.Fatalf("%d topology matches; want 4", len(out.TopologyMatches))
	}
	for _, m := range out.TopologyMatches {
		if m.OldTopology == "" || m.NewTopology == "" || m.MatchedByName != (m.OldFunction == m.NewFunction) {
			t.Errorf("topology match %+v; want both topologies, matched by name only when the names are equal", m)
		}
	}
}

// Results built outside a load have no SSA function: equal fingerprints
// are preserved, different ones modified, without the Zipper's evidence.
func TestCompareFunctions_WithoutSSA(t *testing.T) {
	a, b := diff.FingerprintResult{Fingerprint: "a"}, diff.FingerprintResult{Fingerprint: "b"}
	if d := api.CompareFunctions("F", a, a); d.Status != models.StatusPreserved || !d.FingerprintMatch {
		t.Errorf("equal fingerprints: %+v; want preserved", d)
	}
	want := models.FunctionDiff{Function: "F", Status: models.StatusModified, OldFingerprint: "a", NewFingerprint: "b"}
	if d := api.CompareFunctions("F", a, b); !reflect.DeepEqual(d, want) {
		t.Errorf("different fingerprints: %+v; want %+v", d, want)
	}
}
