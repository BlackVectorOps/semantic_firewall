package api_test

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

const sumGo = `package p
func Sum(a, b int) int { return a + b }
`

// sumUnsafeGo is sumGo importing unsafe, as a //go:linkname directive needs.
const sumUnsafeGo = `package p
import _ "unsafe"
func Sum(a, b int) int { return a + b }
`

// A function declared without a Go body has no SSA, so its code (assembly,
// or a //go:linkname target) is unreadable. Adding one, or changing its
// signature, is high-risk; removing one is not.
func TestDiffRisk_Bodyless(t *testing.T) {
	cases := []struct {
		name, oldSrc, newSrc, fn, status, label string
		high                                    bool
	}{
		{name: "added, assembly", fn: "add", status: models.StatusAdded, label: "NoBody", high: true,
			oldSrc: sumGo,
			newSrc: sumGo + "func add(a, b int) int\n"},
		{name: "added, linkname", fn: "nanotime", status: models.StatusAdded, label: "NoBody", high: true,
			oldSrc: sumUnsafeGo,
			newSrc: sumUnsafeGo + "//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n"},
		{name: "added, no results", fn: "halt", status: models.StatusAdded, label: "NoBody", high: true,
			oldSrc: sumGo,
			newSrc: sumGo + "func halt()\n"},
		{name: "added method", fn: "(*T).add", status: models.StatusAdded, label: "NoBody", high: true,
			oldSrc: sumGo + "type T struct{}\n",
			newSrc: sumGo + "type T struct{}\nfunc (t *T) add(a, b int) int\n"},
		{name: "removed", fn: "add", status: models.StatusRemoved, label: "NoBody", high: false,
			oldSrc: sumGo + "func add(a, b int) int\n",
			newSrc: sumGo},
		{name: "unchanged", fn: "add", status: models.StatusPreserved, label: "", high: false,
			oldSrc: sumGo + "func add(a, b int) int\n",
			newSrc: sumGo + "func add(a, b int) int\n"},
		{name: "parameters renamed", fn: "add", status: models.StatusPreserved, label: "", high: false,
			oldSrc: sumGo + "func add(a, b int) int\n",
			newSrc: sumGo + "func add(x int, y int) (n int)\n"},
		{name: "signature changed", fn: "add", status: models.StatusModified, label: "NoBody, Signature~", high: true,
			oldSrc: sumGo + "func add(a, b int) int\n",
			newSrc: sumGo + "func add(a, b int64) int64\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := findFunc(t, diffSources(t, c.oldSrc, c.newSrc), c.fn)
			if f.Status != c.status || f.TopologyDelta != c.label {
				t.Errorf("%s: status %q, delta %q; want %q, %q", c.fn, f.Status, f.TopologyDelta, c.status, c.label)
			}
			if high := f.RiskScore >= models.RiskScoreHigh; high != c.high {
				t.Errorf("%s: risk %d; want high-risk %v", c.fn, f.RiskScore, c.high)
			}
			if want := c.status == models.StatusPreserved; f.FingerprintMatch != want {
				t.Errorf("%s: fingerprint_match %v; want %v", c.fn, f.FingerprintMatch, want)
			}
		})
	}
}

// Body-less functions count in the summary like any other. A linkname
// directive counts as a high-risk change, not a function.
func TestDiffRisk_BodylessSummary(t *testing.T) {
	out := diffSources(t,
		sumUnsafeGo+"func keep() int\nfunc gone() int\nfunc changed(a int) int\n",
		sumUnsafeGo+"func keep() int\nfunc changed(a int64) int\nfunc add(a, b int) int\n//go:linkname keep example.invalid/q.Keep\n")
	s := out.Summary
	// Sum, keep and init are preserved, changed is modified, add is added and
	// gone is removed: four name-matched pairs out of six functions. The
	// directive is the third high-risk change.
	if s.TotalFunctions != 6 || s.Preserved != 3 || s.Modified != 1 || s.Added != 1 || s.Removed != 1 || s.HighRiskChanges != 3 {
		t.Errorf("summary = %+v; want 6 functions: 3 preserved, 1 modified, 1 added, 1 removed, 3 high-risk", s)
	}
	pct := func(n, total int) float64 { return float64(n) / float64(total) * 100 }
	if s.SemanticMatchPct != pct(3, 6) || s.TopologyMatchedPct != pct(4, 6) {
		t.Errorf("summary = %+v; want %v%% semantic and %v%% topology match", s, pct(3, 6), pct(4, 6))
	}
}

// With no functions on either side, both percentages are 0, not 0/0.
func TestDiff_EmptySummary(t *testing.T) {
	out, err := api.Diff("", "")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if s := out.Summary; s.TotalFunctions != 0 || s.SemanticMatchPct != 0 || s.TopologyMatchedPct != 0 {
		t.Errorf("summary = %+v; want no functions and 0%% matches", s)
	}
}

// linknamePkg is a module whose package p declares hidden without a body
// and writes x. The empty a.s lets hidden build with no directive naming it.
var linknamePkg = map[string]string{
	"go.mod": "module example.invalid/m\n\ngo 1.22\n",
	"q/q.go": "package q\n\nvar secret = 42\n\nfunc Hidden() int { return secret * 2 }\n\nfunc Other() int { return 1 }\n",
	"p/a.go": "package p\n\nvar x int\n\nfunc hidden() int\n\nfunc Get() int { x = 7; return hidden() }\n",
	"p/a.s":  "",
}

// diffLinknamePkg diffs p/b.go between two copies of linknamePkg.
func diffLinknamePkg(t *testing.T, oldSrc, newSrc string) (*models.DiffOutput, string) {
	t.Helper()
	files := map[string]string{"old/p/b.go": oldSrc, "new/p/b.go": newSrc}
	for name, src := range linknamePkg {
		files["old/"+name], files["new/"+name] = src, src
	}
	dir := writeTree(t, files)
	out, err := api.Diff(filepath.Join(dir, "old/p/b.go"), filepath.Join(dir, "new/p/b.go"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	return out, dir
}

// A //go:linkname directive applies package-wide, to a function or variable
// declared in any file, so each one added to a file is high-risk whatever it
// names.
func TestDiffRisk_Linkname(t *testing.T) {
	const base = "package p\n\nimport _ \"unsafe\"\n"
	const toHidden = "//go:linkname hidden example.invalid/m/q.Hidden"
	cases := []struct {
		name, oldSrc, newSrc string
		removed, added       []string
	}{
		{name: "variable", oldSrc: base, newSrc: base + "//go:linkname x example.invalid/m/q.secret\n",
			added: []string{"//go:linkname x example.invalid/m/q.secret"}},
		{name: "function declared in another file", oldSrc: base, newSrc: base + toHidden + "\n",
			added: []string{toHidden}},
		{name: "inside a function body", oldSrc: base + "func f() {}\n", newSrc: base + "func f() {\n\t" + toHidden + "\n}\n",
			added: []string{toHidden}},
		{name: "one-argument form", oldSrc: base, newSrc: base + "//go:linkname Get\n",
			added: []string{"//go:linkname Get"}},
		{name: "linknamestd spelling", oldSrc: base, newSrc: base + "//go:linknamestd x example.invalid/m/q.secret\n",
			added: []string{"//go:linknamestd x example.invalid/m/q.secret"}},
		{name: "target changed", oldSrc: base + toHidden + "\n", newSrc: base + "//go:linkname hidden example.invalid/m/q.Other\n",
			removed: []string{toHidden}, added: []string{"//go:linkname hidden example.invalid/m/q.Other"}},
		{name: "removed", oldSrc: base + toHidden + "\n", newSrc: base,
			removed: []string{toHidden}},
		{name: "spacing changed", oldSrc: base + "//go:linkname  hidden\texample.invalid/m/q.Hidden\n", newSrc: base + toHidden + "\n"},
		{name: "in a block comment", oldSrc: base, newSrc: base + "/*\n" + toHidden + "\n*/\n"},
		{name: "tab after go:linkname", oldSrc: base, newSrc: base + "//go:linkname\thidden example.invalid/m/q.Hidden\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, dir := diffLinknamePkg(t, c.oldSrc, c.newSrc)
			var want []models.FileChange
			for _, d := range c.removed {
				want = append(want, models.FileChange{File: filepath.Join(dir, "old/p/b.go") + ": " + d, Kind: "linkname", Change: "removed"})
			}
			for _, d := range c.added {
				want = append(want, models.FileChange{File: filepath.Join(dir, "new/p/b.go") + ": " + d, Kind: "linkname", Change: "added", RiskScore: models.RiskScoreHigh})
			}
			if !slices.Equal(out.Unanalyzed, want) {
				t.Errorf("unanalyzed = %+v; want %+v", out.Unanalyzed, want)
			}
			if out.Summary.HighRiskChanges != len(c.added) {
				t.Errorf("high_risk_changes = %d; want %d", out.Summary.HighRiskChanges, len(c.added))
			}
		})
	}
}

// Batch mode reports body-less functions and linkname directives as a
// single diff does. Directives compare by text, so a renamed file keeps its.
func TestDiffBatch_Bodyless(t *testing.T) {
	const directive = "//go:linkname nanotime runtime.nanotime"
	withNanotime := sumUnsafeGo + directive + "\nfunc nanotime() int64\n"
	dir := writeTree(t, map[string]string{
		"old/a/x.go": sumUnsafeGo, "new/a/x.go": withNanotime,
		"old/b/y.go": withNanotime, "new/b/z.go": withNanotime,
	})
	got := api.DiffBatch([]api.DiffPair{
		{Old: filepath.Join(dir, "old/a/x.go"), New: filepath.Join(dir, "new/a/x.go")},
		{Old: filepath.Join(dir, "old/b/y.go"), New: filepath.Join(dir, "new/b/z.go")},
	})
	if len(got) != 2 || got[0].ErrorMessage != "" || got[1].ErrorMessage != "" {
		t.Fatalf("DiffBatch = %+v", got)
	}
	f := findFunc(t, got[0], "nanotime")
	if f.Status != models.StatusAdded || f.TopologyDelta != "NoBody" || f.RiskScore < models.RiskScoreHigh {
		t.Errorf("nanotime = %+v; want added, NoBody, high-risk", f)
	}
	want := []models.FileChange{{File: filepath.Join(dir, "new/a/x.go") + ": " + directive, Kind: "linkname", Change: "added", RiskScore: models.RiskScoreHigh}}
	if !slices.Equal(got[0].Unanalyzed, want) || got[0].Summary.HighRiskChanges != 2 {
		t.Errorf("x.go: unanalyzed %+v, %d high-risk; want %+v and 2", got[0].Unanalyzed, got[0].Summary.HighRiskChanges, want)
	}
	if len(got[1].Unanalyzed) != 0 || got[1].Summary.HighRiskChanges != 0 {
		t.Errorf("y.go renamed: unanalyzed %+v, %d high-risk; want none", got[1].Unanalyzed, got[1].Summary.HighRiskChanges)
	}
}

// deps diff does not report a dependency's body-less functions. The empty
// x.s lets add build.
func TestDepsDiff_BodylessNotReported(t *testing.T) {
	imports := "\t_ \"example.com/mathx\"\n"
	deps := map[string]string{"example.com/mathx": "mathx"}
	src := strings.Replace(sumGo, "package p", "package mathx", 1)
	oldDir := appTree(t, imports, deps, map[string]string{"lib/mathx/x.go": src, "lib/mathx/x.s": ""})
	newDir := appTree(t, imports, deps, map[string]string{"lib/mathx/x.go": src + "func add(a, b int) int\n", "lib/mathx/x.s": ""})
	out := depsDiff(t, oldDir, newDir)
	for _, m := range out.Modules {
		for _, p := range m.Packages {
			for _, f := range p.Functions {
				if strings.Contains(f.TopologyDelta, "NoBody") {
					t.Errorf("%s: %s reported with %q", m.Path, f.Function, f.TopologyDelta)
				}
			}
		}
	}
}
