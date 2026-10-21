package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

func writePairs(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pairs")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadDiffPairs(t *testing.T) {
	fsys := RealFileSystem{}
	pairs, err := ReadDiffPairs(fsys, writePairs(t, "a.go\x00b.go\x00\x00c.go\x00"))
	if err != nil {
		t.Fatalf("ReadDiffPairs: %v", err)
	}
	want := []api.DiffPair{{Old: "a.go", New: "b.go"}, {Old: "", New: "c.go"}}
	if len(pairs) != len(want) || pairs[0] != want[0] || pairs[1] != want[1] {
		t.Errorf("pairs = %+v; want %+v", pairs, want)
	}
	if pairs, err := ReadDiffPairs(fsys, writePairs(t, "")); err != nil || len(pairs) != 0 {
		t.Errorf("empty file: pairs %+v, err %v; want none", pairs, err)
	}
	for name, content := range map[string]string{
		"unterminated": "a.go\x00b.go",
		"odd":          "a.go\x00b.go\x00c.go\x00",
	} {
		if _, err := ReadDiffPairs(fsys, writePairs(t, content)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := ReadDiffPairs(fsys, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Errorf("missing pairs file: no error")
	}
}

// The batch prints every result in pair order, and fails after printing
// when a pair could not be diffed.
func TestRunDiffBatchLogic(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldA := write("old_a.go", "package p\n\nfunc A() int { return 1 }\n")
	newA := write("new_a.go", "package p\n\nfunc A() int { return 2 }\n")
	bad := write("bad.go", "package p\n\nfunc B() int { return undefinedThing }\n")

	run := func(pairs string) ([]models.DiffOutput, error) {
		var buf bytes.Buffer
		err := RunDiffBatchLogic(RealFileSystem{}, &buf, writePairs(t, pairs), false)
		var out []models.DiffOutput
		if jerr := json.Unmarshal(buf.Bytes(), &out); jerr != nil {
			t.Fatalf("output is not a JSON array: %v\n%s", jerr, buf.String())
		}
		return out, err
	}

	out, err := run(oldA + "\x00" + newA + "\x00\x00" + newA + "\x00")
	if err != nil {
		t.Fatalf("RunDiffBatchLogic: %v", err)
	}
	status := func(d models.DiffOutput, fn string) string {
		for _, f := range d.Functions {
			if f.Function == fn {
				return f.Status
			}
		}
		return ""
	}
	if len(out) != 2 || out[0].NewFile != newA || status(out[0], "A") != models.StatusModified ||
		out[1].OldFile != "" || status(out[1], "A") != models.StatusAdded {
		t.Errorf("results = %+v; want A modified, then A added", out)
	}

	out, err = run(bad + "\x00" + bad + "\x00" + oldA + "\x00" + newA + "\x00")
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Errorf("error = %v; want 1 of 2 pairs failed", err)
	}
	if len(out) != 2 || out[0].ErrorMessage == "" || out[1].ErrorMessage != "" || status(out[1], "A") != models.StatusModified {
		t.Errorf("results = %+v; want the failed pair's error, then A modified", out)
	}
}

// A sandboxed batch mounts the pairs file and each input's context root
// once; inputs without a root mount their directory.
func TestBatchMounts(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"m/go.mod":      "module example.com/m\n",
		"m/p/a.go":      "package p\n",
		"m/q/b.go":      "package q\n",
		"loose/main.go": "package main\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a, b, loose := filepath.Join(dir, "m/p/a.go"), filepath.Join(dir, "m/q/b.go"), filepath.Join(dir, "loose/main.go")
	if root := findContextRoot(loose); root != "" {
		t.Skipf("%s has a context root %s above the temp dir", loose, root)
	}
	got := batchMounts("pairs", []api.DiffPair{{Old: a, New: b}, {Old: "", New: loose}, {Old: os.DevNull, New: a}})
	want := []string{"pairs", filepath.Join(dir, "m"), loose}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("batchMounts = %v; want %v", got, want)
	}
}

// An empty path is the absent side of an added or removed file for sfw diff
// too, as in a pairs file: it is not cleaned into the current directory.
func TestRunDiff_EmptyPathIsAbsent(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.go")
	if err := os.WriteFile(file, []byte("package p\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = stdout })
	errs := []error{RunDiff("", file, true), RunDiff(file, "", true)}
	w.Close()
	os.Stdout = stdout
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&out)
	for i, want := range []string{models.StatusAdded, models.StatusRemoved} {
		var d models.DiffOutput
		if errs[i] != nil {
			t.Fatalf("diff %d: %v", i, errs[i])
		}
		if err := dec.Decode(&d); err != nil {
			t.Fatalf("diff %d output: %v", i, err)
		}
		found := false
		for _, f := range d.Functions {
			found = found || f.Function == "F" && f.Status == want
		}
		if !found {
			t.Errorf("diff %d: %+v; want F %s", i, d.Functions, want)
		}
	}
}
