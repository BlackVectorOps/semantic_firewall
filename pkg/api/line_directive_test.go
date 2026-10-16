package api_test

import (
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

// A //line directive names another file for the declarations after it.
// The function is still written in the diffed file and must be diffed
// there: before the fix, Handle read as removed with risk 0 and its new
// exec capability was never reported.
func TestDiff_LineDirectiveCannotHideAFunction(t *testing.T) {
	const old = `package x

func Handle(s string) int { return len(s) }
`
	const changed = `package x

import "os/exec"

//line zz.go:1
func Handle(s string) int { exec.Command(s).Run(); return len(s) }
`
	out := diffSources(t, old, changed)
	f := findFunc(t, out, "Handle")
	if f.Status != "modified" {
		t.Errorf("Handle status = %q; want modified", f.Status)
	}
	if f.RiskScore < models.RiskScoreHigh || !strings.Contains(f.TopologyDelta, "Capability+exec(") {
		t.Errorf("Handle risk = %d (%s); want the new exec capability at >= %d", f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
	}
	for _, g := range out.Functions {
		if g.Function == "Handle" && g.Status == "removed" {
			t.Errorf("Handle also reported removed: %+v", out.Functions)
		}
	}
}
