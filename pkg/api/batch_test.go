package api_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

// batchFixture writes two versions of a module (and of a loose file outside
// any module) covering every kind of input a batch can hold, and returns
// the pairs to diff.
func batchFixture(t *testing.T) []api.DiffPair {
	t.Helper()
	gomod := "module example.com/m\n\ngo 1.22\n"
	common := map[string]string{
		"go.mod":       gomod,
		"p/b.go":       "package p\n\n// B is unchanged.\nfunc B(s string) int { return len(s) }\n",
		"e/empty.go":   "  \n",
		"q/helper.go":  "package q\n\nimport (\n\t\"crypto/hmac\"\n\t\"crypto/sha256\"\n)\n\n// Check verifies mac.\nfunc Check(key, msg, mac []byte) bool {\n\tm := hmac.New(sha256.New, key)\n\tm.Write(msg)\n\treturn hmac.Equal(m.Sum(nil), mac)\n}\n",
		"r/syntax.go":  "package r\n\nfunc C() int { return 2 \n",
		"s/typeerr.go": "package s\n\nfunc A() int { return undefinedThing }\n",
	}
	oldFiles := map[string]string{
		"p/a.go":          "package p\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/m/q\"\n)\n\nvar greeting = \"hi\"\n\nfunc Handle(key, msg, mac []byte) {\n\tif !q.Check(key, msg, mac) {\n\t\treturn\n\t}\n\tfmt.Println(greeting, string(msg))\n}\n\nfunc Closure() func() int { return func() int { return 1 } }\n",
		"p/gone.go":       "package p\n\nfunc Gone() {}\n",
		"p/old_name.go":   "package p\n\nfunc Renamed(x int) int { return x * 2 }\n",
		"p/x_windows.go":  "package p\n\nimport \"fmt\"\n\nfunc Win(c string) { fmt.Println(c) }\n",
		"p/tagged.go":     "//go:build integration\n\npackage p\n\nfunc Seed(s string) int { return len(s) }\n",
		"p/a_test.go":     "package p\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
		"q/q.go":          "package q\n\nvar Mode = 1\n\nfunc Q() int { return Mode }\n",
		"loose/script.go": "package main\n\nfunc main() { println(1) }\n",
	}
	newFiles := map[string]string{
		"p/a.go":          "package p\n\nimport (\n\t\"fmt\"\n\t\"os/exec\"\n)\n\nvar greeting = \"hello\"\n\nfunc Handle(key, msg, mac []byte) {\n\tfmt.Println(greeting, string(msg))\n\texec.Command(string(msg)).Run()\n}\n\nfunc Closure() func() int { return func() int { return 2 } }\n",
		"p/new.go":        "package p\n\nimport \"net\"\n\nfunc Added(a string) { net.Dial(\"tcp\", a) }\n",
		"p/new_name.go":   "package p\n\nfunc Renamed(x int) int { return x * 2 }\n",
		"p/x_windows.go":  "package p\n\nimport \"net\"\n\nfunc Win(c string) { net.Dial(\"tcp\", c) }\n",
		"p/tagged.go":     "//go:build integration\n\npackage p\n\nimport \"os\"\n\nfunc Seed(s string) int { os.RemoveAll(s); return len(s) }\n",
		"p/a_test.go":     "package p\n\nimport (\n\t\"os/exec\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) { exec.Command(\"x\").Run() }\n",
		"q/q.go":          "package q\n\nvar Mode = 2\n\nfunc Q() int { return Mode + 1 }\n",
		"loose/script.go": "package main\n\nimport \"os\"\n\nfunc main() { os.Remove(\"x\") }\n",
	}
	root := t.TempDir()
	write := func(side string, files map[string]string) {
		for name, src := range files {
			p := filepath.Join(root, side, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, side := range []string{"old", "new"} {
		write(side, common)
	}
	write("old", oldFiles)
	write("new", newFiles)
	// The loose file lives outside the module.
	for _, side := range []string{"old", "new"} {
		src := filepath.Join(root, side, "loose", "script.go")
		dst := filepath.Join(root, side+"-loose", "script.go")
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(src, dst); err != nil {
			t.Fatal(err)
		}
	}
	o := func(name string) string { return filepath.Join(root, "old", name) }
	n := func(name string) string { return filepath.Join(root, "new", name) }
	return []api.DiffPair{
		{o("p/a.go"), n("p/a.go")},
		{o("p/b.go"), n("p/b.go")},
		{o("q/q.go"), n("q/q.go")},
		{o("q/helper.go"), n("q/helper.go")},
		{o("p/new.go"), n("p/new.go")},           // added: old side missing
		{o("p/gone.go"), n("p/gone.go")},         // removed: new side missing
		{"", n("p/new.go")},                      // added: empty old path
		{o("p/old_name.go"), n("p/new_name.go")}, // renamed
		{o("e/empty.go"), n("e/empty.go")},       // whitespace only
		{os.DevNull, n("p/b.go")},                // /dev/null old side
		{o("p/x_windows.go"), n("p/x_windows.go")},
		{o("p/tagged.go"), n("p/tagged.go")},
		{o("p/a_test.go"), n("p/a_test.go")},
		{o("r/syntax.go"), n("r/syntax.go")},
		{o("s/typeerr.go"), n("s/typeerr.go")},
		{filepath.Join(root, "old-loose", "script.go"), filepath.Join(root, "new-loose", "script.go")},
		{o("p/a.go"), n("p/a.go")}, // the same pair twice
	}
}

// singleDiff is what a batch entry must equal: Diff's result, or for an
// error the entry DiffBatch documents.
func singleDiff(p api.DiffPair) *models.DiffOutput {
	out, err := api.Diff(p.Old, p.New)
	if err != nil {
		return &models.DiffOutput{OldFile: p.Old, NewFile: p.New, Functions: []models.FunctionDiff{}, ErrorMessage: err.Error()}
	}
	return out
}

// Every batch entry is byte-for-byte the single-file diff of its pair.
func TestDiffBatch_EqualsSingleDiffs(t *testing.T) {
	pairs := batchFixture(t)
	got := api.DiffBatch(pairs)
	if len(got) != len(pairs) {
		t.Fatalf("got %d results for %d pairs", len(got), len(pairs))
	}
	for i, p := range pairs {
		want, _ := json.Marshal(singleDiff(p))
		have, _ := json.Marshal(got[i])
		if string(want) != string(have) {
			t.Errorf("pair %d (%s -> %s):\n batch  %s\n single %s", i, filepath.Base(p.Old), filepath.Base(p.New), have, want)
		}
	}

	// The fixture must exercise what it claims to: real results, and the
	// errors the broken packages produce.
	byName := func(i int, name string) *models.FunctionDiff {
		for j, f := range got[i].Functions {
			if f.Function == name {
				return &got[i].Functions[j]
			}
		}
		return nil
	}
	if f := byName(0, "Handle"); f == nil || f.RiskScore < models.RiskScoreHigh {
		t.Errorf("p/a.go: Handle = %+v; want a high-risk change", f)
	}
	for _, i := range []int{10, 11, 12} {
		if got[i].ErrorMessage != "" || got[i].Summary.HighRiskChanges == 0 {
			t.Errorf("pair %d (%s): error %q, %d high-risk; want a high-risk diff", i, filepath.Base(pairs[i].New), got[i].ErrorMessage, got[i].Summary.HighRiskChanges)
		}
	}
	for _, i := range []int{13, 14} {
		if got[i].ErrorMessage == "" {
			t.Errorf("pair %d (%s): no error; want the ill-typed package's error", i, filepath.Base(pairs[i].New))
		}
	}
	if f := byName(15, "main"); f == nil || f.Status != models.StatusModified {
		t.Errorf("loose file: main = %+v; want modified", f)
	}
}
