package api_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
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

// sameAsSingles reports every batch entry that is not its pair's single
// result.
func sameAsSingles(t *testing.T, pairs []api.DiffPair, got []*models.DiffOutput, single func(api.DiffPair) *models.DiffOutput) {
	t.Helper()
	for i, p := range pairs {
		want, _ := json.Marshal(single(p))
		have, _ := json.Marshal(got[i])
		if string(want) != string(have) {
			t.Errorf("pair %d (%s):\n batch  %s\n single %s", i, filepath.Base(p.New), have, want)
		}
	}
}

// A function of another package that claims the diffed file with a //line
// directive is no function of the file: Diff loads only the file's own
// package, and a batch that loads both must not let the decoy stand in for
// the changed function.
func TestDiffBatch_LineDirectiveFromAnotherPackage(t *testing.T) {
	root := t.TempDir()
	writeFilesIn(t, root, map[string]string{
		"old/go.mod":   "module example.com/m\n\ngo 1.22\n",
		"old/p/a.go":   "package p\n\nfunc Handle(s string) int { return len(s) }\n",
		"old/zz/zz.go": "package zz\n\nfunc Z() int { return 1 }\n",
		"new/go.mod":   "module example.com/m\n\ngo 1.22\n",
		"new/p/a.go":   "package p\n\nimport \"os/exec\"\n\nfunc Handle(s string) int {\n\texec.Command(s).Run()\n\treturn len(s)\n}\n",
		"new/zz/zz.go": "package zz\n\nfunc Z() int { return 1 }\n\n//line ../p/a.go:3\nfunc Handle(s string) int { return len(s) }\n",
	})
	o := func(n string) string { return filepath.Join(root, "old", n) }
	n := func(n string) string { return filepath.Join(root, "new", n) }
	pairs := []api.DiffPair{{Old: o("p/a.go"), New: n("p/a.go")}, {Old: o("zz/zz.go"), New: n("zz/zz.go")}}
	got := api.DiffBatch(pairs)
	sameAsSingles(t, pairs, got, singleDiff)
	if got[0].Summary.HighRiskChanges != 1 {
		t.Errorf("p/a.go: %+v; want Handle's exec as one high-risk change", got[0].Summary)
	}
}

// A batch loads each file with the workspace Diff loads it with, also when
// a .git entry between the file and its module root (a submodule) ends the
// workspace search for that file alone. Here Diff, without the workspace,
// cannot resolve example.com/lib, and the batch must fail the same way.
func TestDiffBatch_WorkspacePerFile(t *testing.T) {
	root := t.TempDir()
	writeFilesIn(t, root, map[string]string{
		".git/HEAD":    "ref: refs/heads/main\n",
		"go.work":      "go 1.22\n\nuse (\n\t./m\n\t./lib\n)\n",
		"lib/go.mod":   "module example.com/lib\n\ngo 1.22\n",
		"lib/lib.go":   "package lib\n\nfunc F() int { return 1 }\n",
		"m/go.mod":     "module example.com/m\n\ngo 1.22\n",
		"m/a.go":       "package m\n\nimport \"example.com/lib\"\n\nfunc A() int { return lib.F() }\n",
		"m/third/.git": "gitdir: ../../.git/modules/third\n",
		"m/third/x.go": "package third\n\nimport \"example.com/lib\"\n\nfunc X() int { return lib.F() }\n",
	})
	pairs := []api.DiffPair{{New: filepath.Join(root, "m", "a.go")}, {New: filepath.Join(root, "m", "third", "x.go")}}
	got := api.DiffBatch(pairs)
	sameAsSingles(t, pairs, got, singleDiff)
	if got[0].ErrorMessage != "" || got[1].ErrorMessage == "" {
		t.Errorf("errors %q, %q; want a.go to load with the workspace and x.go to fail without it", got[0].ErrorMessage, got[1].ErrorMessage)
	}
}

// overlayFS is the disk with some files' contents replaced, as an editor
// serving unsaved buffers would be.
type overlayFS struct {
	api.RealFileSystem
	files map[string][]byte
}

type sizedInfo struct {
	os.FileInfo
	size int64
}

func (i sizedInfo) Size() int64 { return i.size }

func (f overlayFS) Stat(name string) (os.FileInfo, error) {
	info, err := os.Stat(name)
	if src, ok := f.files[name]; ok && err == nil {
		return sizedInfo{info, int64(len(src))}, nil
	}
	return info, err
}

func (f overlayFS) ReadFile(name string) ([]byte, error) {
	if src, ok := f.files[name]; ok {
		return src, nil
	}
	return f.RealFileSystem.ReadFile(name)
}

// Against a FileSystem other than the disk, each entry is what DiffWithFS
// returns for its pair, which reads the file's package siblings from disk:
// another pair's file served by the FileSystem changes nothing.
func TestDiffBatchWithFS_EqualsDiffWithFS(t *testing.T) {
	root := t.TempDir()
	writeFilesIn(t, root, map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n",
		"p/a.go": "package p\n\nimport \"os\"\n\nfunc Clean(dir string) {\n\tif Debug {\n\t\treturn\n\t}\n\tos.RemoveAll(dir)\n}\n",
		"p/b.go": "package p\n\nconst Debug = false\n",
	})
	a, b := filepath.Join(root, "p", "a.go"), filepath.Join(root, "p", "b.go")
	fsys := overlayFS{files: map[string][]byte{b: []byte("package p\n\nconst Debug = true\n")}}
	pairs := []api.DiffPair{{New: a}, {New: b}}
	sameAsSingles(t, pairs, api.DiffBatchWithFS(fsys, pairs), func(p api.DiffPair) *models.DiffOutput {
		out, err := api.DiffWithFS(fsys, p.Old, p.New)
		if err != nil {
			return &models.DiffOutput{OldFile: p.Old, NewFile: p.New, Functions: []models.FunctionDiff{}, ErrorMessage: err.Error()}
		}
		return out
	})
}

// A batch applies Diff's input rules to each path: an empty path, a missing
// file and a file of only whitespace have no functions; a stat or read
// error and a file over models.MaxSourceFileSize fail their pair, the old
// side's error first; a file of exactly the limit is diffed.
func TestDiffBatch_InputRules(t *testing.T) {
	root := t.TempDir()
	src := "package p\n\nfunc F() int { return 1 }\n"
	pad := func(size int) string { return src + "//" + strings.Repeat("x", size-len(src)-3) + "\n" }
	writeFilesIn(t, root, map[string]string{
		"go.mod":      "module example.com/m\n\ngo 1.22\n",
		"p/a.go":      src,
		"blank/b.go":  "\n\t \n",
		"q/limit.go":  pad(models.MaxSourceFileSize),
		"r/big.go":    pad(models.MaxSourceFileSize + 1),
		"s/dir.go/x":  "",
		"loose/b.txt": "",
	})
	path := func(name string) string { return filepath.Join(root, filepath.FromSlash(name)) }
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, path("p/a.go"))
	if err != nil {
		t.Fatal(err)
	}
	pairs := []api.DiffPair{
		{Old: "", New: path("p/a.go")},
		{Old: "", New: rel},
		{Old: path("p/missing.go"), New: path("p/a.go")},
		{Old: path("blank/b.go"), New: path("p/a.go")},
		{Old: "", New: path("q/limit.go")},
		{Old: path("r/big.go"), New: path("p/a.go")},
		{Old: path("p/a.go"), New: path("r/big.go")},
		{Old: path("p/a.go/x.go"), New: path("p/a.go")},
		{Old: path("p/a.go"), New: path("s/dir.go")},
		{Old: path("r/big.go"), New: path("s/dir.go")},
	}
	got := api.DiffBatch(pairs)
	sameAsSingles(t, pairs, got, singleDiff)
	for i, want := range []string{
		"", "", "", "", "",
		"failed to process old file: file " + path("r/big.go") + " exceeds maximum analysis size",
		"failed to process new file: file " + path("r/big.go") + " exceeds maximum analysis size",
		"failed to process old file: failed to stat " + path("p/a.go/x.go"),
		"failed to process new file: path is a directory: " + path("s/dir.go"),
		"failed to process old file: file " + path("r/big.go"),
	} {
		if msg := got[i].ErrorMessage; want == "" && (msg != "" || len(got[i].Functions) == 0) || !strings.HasPrefix(msg, want) {
			t.Errorf("pair %d: error %q, %d functions; want %q", i, msg, len(got[i].Functions), want)
		}
	}
}

// statErrFS fails every Stat that is not of an existing file with an error
// other than "not found".
type statErrFS struct{ api.RealFileSystem }

func (statErrFS) Stat(name string) (os.FileInfo, error) {
	if info, err := os.Stat(name); err == nil {
		return info, nil
	}
	return nil, os.ErrPermission
}

// An empty path stands for an absent file whatever the FileSystem says
// about it.
func TestDiffBatchWithFS_EmptyPathIsAbsent(t *testing.T) {
	a := filepath.Join(t.TempDir(), "a.go")
	if err := os.WriteFile(a, []byte("package p\n\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := api.DiffBatchWithFS(statErrFS{}, []api.DiffPair{{Old: "", New: a}})
	if got[0].ErrorMessage != "" || len(got[0].Functions) == 0 {
		t.Errorf("error %q, %d functions; want F added", got[0].ErrorMessage, len(got[0].Functions))
	}
}

// A batch of one pair loads with one file= query, which go list answers
// for a file that is the only Go file of its directory and outside the host
// build with an ad-hoc package of the file under the host's GOOS and GOARCH. Diff loads the file under its
// own configuration; the batch must give Diff's result, so such a package
// is not used (the host's sizes would change Size's fingerprint).
func TestDiffBatch_OnePairOutsideTheHostBuild(t *testing.T) {
	oldDir, newDir := writeModule(t, nil,
		map[string]string{"s/size_386.go": "package s\n\nimport \"unsafe\"\n\nfunc Size() int { return int(unsafe.Sizeof(uintptr(0))) }\n"},
		map[string]string{"s/size_386.go": "package s\n\nimport \"unsafe\"\n\nfunc Size() int { return int(unsafe.Sizeof(uintptr(0))) + 1 }\n"})
	pair := api.DiffPair{Old: filepath.Join(oldDir, "s", "size_386.go"), New: filepath.Join(newDir, "s", "size_386.go")}
	got := api.DiffBatch([]api.DiffPair{pair})
	want, _ := json.Marshal(singleDiff(pair))
	have, _ := json.Marshal(got[0])
	if string(want) != string(have) {
		t.Errorf("batch  %s\nsingle %s", have, want)
	}
	if f := findFunc(t, got[0], "Size"); f.Status != models.StatusModified {
		t.Errorf("Size: %+v; want modified", f)
	}
}
