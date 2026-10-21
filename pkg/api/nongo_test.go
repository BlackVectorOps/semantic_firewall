package api_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// With NonGo, a batch pair with no Go file is listed under unanalyzed when
// either tree's build uses the file and its content or use changed.
func TestDiffBatch_NonGoFiles(t *testing.T) {
	const gomod = "module example.invalid/m\n\ngo 1.22\n"
	const pkg = "package p\n\nimport _ \"embed\"\n\n//go:embed payload.txt\nvar payload string\n\nfunc add(a, b int) int\n"
	const plain = "package q\n\nfunc Q() int { return 1 }\n"
	dir := writeTree(t, map[string]string{
		"base/go.mod":        gomod,
		"base/p/p.go":        pkg,
		"base/p/add_amd64.s": "// v1\n",
		"base/p/gone.s":      "// gone\n",
		"base/p/payload.txt": "data\n",
		"base/p/same.s":      "// same\n",
		"head/go.mod":        gomod,
		"head/p/p.go":        pkg,
		"head/p/add_amd64.s": "// v2\n",
		"head/p/payload.txt": "changed\n",
		"head/p/blob.syso":   "\x7fELF....",
		"head/p/same.s":      "// same\n",
		"head/p/notes.txt":   "not embedded\n",
		// No assembly or cgo here, so only what the build names counts.
		"qbase/go.mod":     gomod,
		"qbase/q/q.go":     plain,
		"qhead/go.mod":     gomod,
		"qhead/q/q.go":     plain,
		"qhead/q/notes.md": "docs\n",
		"qhead/q/x.c":      "int x;\n",
		// ./... skips _impl, but q imports it.
		"qbase/r/r.go":            "package r\n\nimport _ \"example.invalid/m/r/_impl\"\n",
		"qbase/r/_impl/impl.go":   "package impl\n",
		"qhead/r/r.go":            "package r\n\nimport _ \"example.invalid/m/r/_impl\"\n",
		"qhead/r/_impl/impl.go":   "package impl\n",
		"qhead/r/_impl/x.syso":    "\x7fELF....",
		"head/assets/payload.bin": "\x7fELF....",
		"loose/outside.s":         "// no module\n",
	})
	at := func(p string) string { return filepath.Join(dir, p) }
	pairs := []api.DiffPair{
		{Old: at("base/p/add_amd64.s"), New: at("head/p/add_amd64.s")},
		{Old: at("base/p/payload.txt"), New: at("head/p/payload.txt")},
		{Old: os.DevNull, New: at("head/p/blob.syso")},
		{Old: at("base/p/gone.s"), New: os.DevNull},
		{Old: at("base/p/same.s"), New: at("head/p/same.s")},
		// In a module with assembly, any file can be #included.
		{Old: os.DevNull, New: at("head/p/notes.txt")},
		{Old: os.DevNull, New: at("qhead/q/notes.md")},
		// A C file beside a package's Go files counts, cgo or not.
		{Old: os.DevNull, New: at("qhead/q/x.c")},
		{Old: os.DevNull, New: at("loose/outside.s")},
		{Old: os.DevNull, New: at("qhead/r/_impl/x.syso")},
		{Old: os.DevNull, New: at("head/assets/payload.bin")},
	}
	want := []*models.FileChange{
		{Kind: "assembly", Change: "modified", RiskScore: 10},
		{Kind: "embed", Change: "modified", RiskScore: 5},
		{Kind: "syso", Change: "added", RiskScore: 20},
		{Kind: "assembly", Change: "removed"},
		nil,
		{Kind: "other", Change: "added", RiskScore: 5},
		nil,
		{Kind: "c", Change: "added", RiskScore: 10},
		nil,
		{Kind: "syso", Change: "added", RiskScore: 20},
		{Kind: "object", Change: "added", RiskScore: 20},
	}
	got := api.DiffBatchWithOptions(api.RealFileSystem{}, pairs, api.BatchOptions{NonGo: true})
	for i, out := range got {
		name := filepath.Base(pairs[i].New)
		if pairs[i].New == os.DevNull {
			name = filepath.Base(pairs[i].Old)
		}
		if out.ErrorMessage != "" || len(out.Functions) != 0 {
			t.Errorf("%s: error %q, functions %v; want neither", name, out.ErrorMessage, out.Functions)
		}
		w := want[i]
		if w == nil {
			if len(out.Unanalyzed) != 0 {
				t.Errorf("%s: unanalyzed %+v; want none", name, out.Unanalyzed)
			}
			continue
		}
		if len(out.Unanalyzed) != 1 {
			t.Errorf("%s: unanalyzed %+v; want one %+v", name, out.Unanalyzed, *w)
			continue
		}
		u := out.Unanalyzed[0]
		if u.Kind != w.Kind || u.Change != w.Change || u.RiskScore != w.RiskScore {
			t.Errorf("%s: unanalyzed %+v; want %+v", name, u, *w)
		}
		if (out.Summary.HighRiskChanges == 1) != (u.RiskScore >= models.RiskScoreHigh) {
			t.Errorf("%s: high_risk_changes %d with risk %d", name, out.Summary.HighRiskChanges, u.RiskScore)
		}
	}

	// Without NonGo, such a pair is loaded as Go and fails.
	if out := api.DiffBatch(pairs[:1])[0]; out.ErrorMessage == "" {
		t.Errorf("without NonGo: %+v; want an error", out)
	}
	// A tree whose packages can't be listed fails its pairs.
	broken := writeTree(t, map[string]string{"go.mod": "module broken\n\ngo 1.22\nrequire (\n", "p/a.s": "// a\n"})
	if out := api.DiffBatchWithOptions(api.RealFileSystem{}, []api.DiffPair{{Old: os.DevNull, New: filepath.Join(broken, "p/a.s")}}, api.BatchOptions{NonGo: true})[0]; out.ErrorMessage == "" {
		t.Errorf("broken module: %+v; want an error", out)
	}
}
