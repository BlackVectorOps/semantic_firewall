package api_test

import (
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// go/ssa names a package's declared init functions init#1, init#2, ... in
// file order across the whole package, so the number of b.go's init depends
// on its siblings, exactly as a closure's number depends on the closures
// created before it. Closures are paired by content for that ("F$1 →
// F$2" keeps its status), and so are the declared inits.
//
// Here b.go is byte-for-byte unchanged; only a new sibling a.go with its own
// init was added to the package. b.go's init is preserved; the diff of the
// unchanged file has no renamed, added or removed function (the package
// initializer "init", which now also calls a.go's init, may be modified).
// Paired by name, a changed init would read as removed + added instead, and
// the added copy would score every capability it already had as new (see
// TestDiff_InitRenumberedKeepsItsCapabilities).
func TestDiff_InitRenumberedBySibling(t *testing.T) {
	b := map[string]string{"b.go": "package p\n\nvar registry []string\n\nfunc init() { registry = append(registry, \"b\") }\n"}
	oldDir, newDir := writeModule(t, b, nil,
		map[string]string{"a.go": "package p\n\nfunc init() { registry = append(registry, \"a\") }\n"})
	out, err := api.Diff(filepath.Join(oldDir, "b.go"), filepath.Join(newDir, "b.go"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, f := range out.Functions {
		t.Logf("%-16s %-10s risk=%d %s", f.Function, f.Status, f.RiskScore, f.TopologyDelta)
	}
	if s := out.Summary; s.RenamedFunctions != 0 || s.Added != 0 || s.Removed != 0 {
		t.Errorf("diff of unchanged b.go: summary %+v; want no renamed, added or removed function", s)
	}
}

// b.go's init already ran a command; the change adds one branch, and a new
// sibling's init renumbers it. Paired with its old version it is modified
// and scores the branch (1): no added or removed function, no high-risk
// change, where a fresh copy would score exec as newly reached.
func TestDiff_InitRenumberedKeepsItsCapabilities(t *testing.T) {
	oldDir, newDir := writeModule(t, nil,
		map[string]string{"b.go": "package p\n\nimport \"os/exec\"\n\nvar Path string\n\nfunc init() {\n\texec.Command(Path).Run()\n}\n"},
		map[string]string{
			"a.go": "package p\n\nvar n int\n\nfunc init() { n = 1 }\n",
			"b.go": "package p\n\nimport \"os/exec\"\n\nvar Path string\n\nfunc init() {\n\tif Path == \"\" {\n\t\treturn\n\t}\n\texec.Command(Path).Run()\n}\n",
		})
	out, err := api.Diff(filepath.Join(oldDir, "b.go"), filepath.Join(newDir, "b.go"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, f := range out.Functions {
		t.Logf("%-16s %-10s risk=%d %s", f.Function, f.Status, f.RiskScore, f.TopologyDelta)
	}
	if out.Summary.HighRiskChanges != 0 || out.Summary.Added != 0 || out.Summary.Removed != 0 {
		t.Errorf("summary %+v; want b.go's init %s (one new branch), no added/removed function and no high-risk change", out.Summary, models.StatusModified)
	}
}
