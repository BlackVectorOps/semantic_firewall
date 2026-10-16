package api_test

import (
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// A //line directive inside the diffed file must not move one of the file's
// own functions out of its diff. Handle below is declared in a.go; the
// directive only changes the position the compiler reports for it.
// Handle is reported as modified, with the new exec capability as a
// high-risk change, as it is without the directive.
func TestDiff_LineDirectiveKeepsChangedFunction(t *testing.T) {
	oldDir, newDir := writeModule(t, nil,
		map[string]string{"a.go": "package p\n\nfunc Handle(s string) int { return len(s) }\n"},
		map[string]string{"a.go": "package p\n\nimport \"os/exec\"\n\n//line zz.go:1\nfunc Handle(s string) int {\n\texec.Command(s).Run()\n\treturn len(s)\n}\n"})
	out, err := api.Diff(filepath.Join(oldDir, "a.go"), filepath.Join(newDir, "a.go"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, f := range out.Functions {
		t.Logf("%-8s %-10s risk=%d %s", f.Function, f.Status, f.RiskScore, f.TopologyDelta)
	}
	f := findFunc(t, out, "Handle")
	if f.Status != models.StatusModified || f.RiskScore < models.RiskScoreHigh || out.Summary.HighRiskChanges == 0 {
		t.Errorf("Handle: status %q risk %d, summary high_risk_changes %d; want modified, risk >= %d, 1 high-risk change",
			f.Status, f.RiskScore, out.Summary.HighRiskChanges, models.RiskScoreHigh)
	}
	// The batch (what the GitHub Action runs) filters the same way.
	batch := api.DiffBatch([]api.DiffPair{{Old: filepath.Join(oldDir, "a.go"), New: filepath.Join(newDir, "a.go")}})
	if batch[0].Summary.HighRiskChanges == 0 {
		t.Errorf("DiffBatch: summary %+v; want 1 high-risk change", batch[0].Summary)
	}
}

// Nor may a directive move a new function into another file's diff: b.go's
// new Evil claims a.go. The diff of b.go, the only changed file and the one
// the GitHub Action diffs, reports Evil as added and high-risk; the diff of
// the unchanged a.go reports nothing new.
func TestDiff_LineDirectiveKeepsAddedFunctionInItsFile(t *testing.T) {
	a := map[string]string{"a.go": "package p\n\nfunc A() int { return 1 }\n"}
	oldDir, newDir := writeModule(t, a,
		map[string]string{"b.go": "package p\n\nfunc B() int { return 2 }\n"},
		map[string]string{"b.go": "package p\n\nimport \"os/exec\"\n\nfunc B() int { return 2 }\n\n//line a.go:100\nfunc Evil(s string) { exec.Command(s).Run() }\n"})
	has := func(out *models.DiffOutput, name string) bool {
		for _, f := range out.Functions {
			if f.Function == name {
				return true
			}
		}
		return false
	}
	t.Run("b.go, where Evil is declared", func(t *testing.T) {
		out, err := api.Diff(filepath.Join(oldDir, "b.go"), filepath.Join(newDir, "b.go"))
		if err != nil {
			t.Fatalf("Diff: %v", err)
		}
		if !has(out, "Evil") || out.Summary.HighRiskChanges == 0 {
			t.Errorf("diff of b.go: Evil reported %v, %d high-risk changes; want Evil added as a high-risk change", has(out, "Evil"), out.Summary.HighRiskChanges)
		}
	})
	t.Run("a.go, unchanged", func(t *testing.T) {
		out, err := api.Diff(filepath.Join(oldDir, "a.go"), filepath.Join(newDir, "a.go"))
		if err != nil {
			t.Fatalf("Diff: %v", err)
		}
		if has(out, "Evil") || out.Summary.Added != 0 {
			t.Errorf("diff of unchanged a.go: Evil reported %v, summary %+v; want no added function", has(out, "Evil"), out.Summary)
		}
	})
}
