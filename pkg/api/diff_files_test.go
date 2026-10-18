package api_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// writeModule creates old/ and new/ module trees sharing the given files,
// overridden per side by oldFiles and newFiles, and returns both roots.
func writeModule(t *testing.T, shared, oldFiles, newFiles map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(side string, files map[string]string) {
		for name, src := range files {
			p := filepath.Join(dir, side, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, side := range []string{"old", "new"} {
		write(side, map[string]string{"go.mod": "module example.com/m\n\ngo 1.22\n"})
		write(side, shared)
	}
	write("old", oldFiles)
	write("new", newFiles)
	return filepath.Join(dir, "old"), filepath.Join(dir, "new")
}

// Files the host build excludes (another GOOS, a _test.go file, a custom
// build tag) are still diffed, and only their own functions are reported.
func TestDiff_FilesOutsideTheHostBuild(t *testing.T) {
	sib := map[string]string{"sib.go": "package p\n\nfunc Sib() int { return 1 }\n"}
	cases := []struct {
		name, file, fn, oldSrc, newSrc string
	}{
		{"GOOS suffix", "x_windows.go", "Handle",
			"package p\n\nimport \"fmt\"\n\nfunc Handle(cmd string) { fmt.Println(cmd) }\n",
			"package p\n\nimport \"net\"\n\nfunc Handle(cmd string) { net.Dial(\"tcp\", cmd) }\n"},
		{"go:build tag", "tagged.go", "Seed",
			"//go:build integration\n\npackage p\n\nfunc Seed(p string) int { return len(p) }\n",
			"//go:build integration && !race\n\npackage p\n\nimport \"os\"\n\nfunc Seed(p string) int { os.RemoveAll(p); return len(p) }\n"},
		{"test file", "a_test.go", "TestX",
			"package p\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
			"package p\n\nimport (\n\t\"os/exec\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) { exec.Command(\"x\").Run() }\n"},
		// For a file that is the only Go file of its directory, go list has
		// no package to leave it out of: it builds an ad-hoc package of the
		// file under the host's GOOS and GOARCH, where its platform's API is
		// undefined and its sizes are the host's. It must be loaded under its
		// own configuration, as a file with siblings is.
		{"GOOS suffix alone in its directory", "w/dll_windows.go", "Load",
			"package w\n\nimport \"syscall\"\n\nfunc Load(n string) *syscall.LazyDLL { return syscall.NewLazyDLL(n) }\n",
			"package w\n\nimport (\n\t\"os/exec\"\n\t\"syscall\"\n)\n\nfunc Load(n string) *syscall.LazyDLL { exec.Command(n).Run(); return syscall.NewLazyDLL(n) }\n"},
		{"GOARCH suffix alone in its directory", "s/size_386.go", "Size",
			"package s\n\nimport \"unsafe\"\n\nvar _ [4 - unsafe.Sizeof(int(0))]byte\n\nfunc Size() int { return int(unsafe.Sizeof(uintptr(0))) }\n",
			"package s\n\nimport (\n\t\"os/exec\"\n\t\"unsafe\"\n)\n\nvar _ [4 - unsafe.Sizeof(int(0))]byte\n\nfunc Size() int { exec.Command(\"x\").Run(); return int(unsafe.Sizeof(uintptr(0))) }\n"},
		// A //go:build ignore script beside the package's files is in no
		// configuration's package (the ignore tag cannot be supplied: the
		// standard library's generators carry it). It is loaded alone.
		{"ignored script", "gen.go", "main",
			"//go:build ignore\n\npackage main\n\nfunc main() { println(1) }\n",
			"//go:build ignore\n\npackage main\n\nimport \"os/exec\"\n\nfunc main() { exec.Command(\"x\").Run() }\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldDir, newDir := writeModule(t, sib, map[string]string{c.file: c.oldSrc}, map[string]string{c.file: c.newSrc})
			out, err := api.Diff(filepath.Join(oldDir, c.file), filepath.Join(newDir, c.file))
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}
			if f := findFunc(t, out, c.fn); f.RiskScore < models.RiskScoreHigh {
				t.Errorf("%s: risk %d (%s); want >= %d", c.fn, f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
			}
			for _, f := range out.Functions {
				if f.Function == "Sib" {
					t.Errorf("sibling function Sib reported in a diff of %s", c.file)
				}
			}
		})
	}
}

// A diff of one file reports that file's functions, not its siblings'.
func TestDiff_OnlyTheDiffedFile(t *testing.T) {
	a := map[string]string{"a.go": "package p\n\nfunc A(s string) string { return s }\n"}
	oldDir, newDir := writeModule(t, a,
		map[string]string{"b.go": "package p\n\nimport \"fmt\"\n\nfunc B(s string) { fmt.Println(s) }\n"},
		map[string]string{"b.go": "package p\n\nimport \"os/exec\"\n\nfunc B(s string) { exec.Command(s).Run() }\n"})
	out, err := api.Diff(filepath.Join(oldDir, "a.go"), filepath.Join(newDir, "a.go"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, f := range out.Functions {
		if f.Function == "B" {
			t.Errorf("diff of unchanged a.go reported sibling B: %+v", f)
		}
	}
	if out.Summary.HighRiskChanges != 0 {
		t.Errorf("diff of unchanged a.go has %d high-risk changes", out.Summary.HighRiskChanges)
	}
	if f := findFunc(t, out, "A"); f.Status != models.StatusPreserved {
		t.Errorf("A: status %q; want preserved", f.Status)
	}
}

// A package whose last path element contains a dot is stripped from the
// reported names completely.
func TestDiff_DottedModulePathNames(t *testing.T) {
	gomod := map[string]string{"go.mod": "module example.com/lib.v2\n\ngo 1.22\n"}
	oldDir, newDir := writeModule(t, gomod,
		map[string]string{"a.go": "package lib\n\ntype T struct{}\n\nfunc (t *T) M() int { return 1 }\n\nfunc F() int { return 1 }\n"},
		map[string]string{"a.go": "package lib\n\ntype T struct{}\n\nfunc (t *T) M() int { return 2 }\n\nfunc F() int { return 2 }\n"})
	out, err := api.Diff(filepath.Join(oldDir, "a.go"), filepath.Join(newDir, "a.go"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	var got []string
	for _, f := range out.Functions {
		got = append(got, f.Function)
	}
	for _, m := range out.TopologyMatches {
		got = append(got, m.OldFunction, m.NewFunction)
	}
	for _, name := range got {
		if strings.Contains(name, "v2") {
			t.Errorf("reported name %q keeps part of the package path", name)
		}
	}
	findFunc(t, out, "(*T).M")
	findFunc(t, out, "F")
}

// A module with a vendor directory is diffed with its dependencies from it,
// as the go command builds it, whatever the module cache holds: the vendored
// module here is in no cache and has no go.sum entry.
func TestDiff_VendoredModule(t *testing.T) {
	shared := map[string]string{
		"go.mod":                        "module example.com/m\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
		"vendor/modules.txt":            "# example.com/dep v1.0.0\n## explicit; go 1.22\nexample.com/dep\n",
		"vendor/example.com/dep/dep.go": "package dep\n\nfunc Run(s string) string { return s }\n",
	}
	oldDir, newDir := writeModule(t, shared,
		map[string]string{"a.go": "package m\n\nimport \"example.com/dep\"\n\nfunc F(s string) string { return dep.Run(s) }\n"},
		map[string]string{"a.go": "package m\n\nimport (\n\t\"os/exec\"\n\n\t\"example.com/dep\"\n)\n\nfunc F(s string) string { exec.Command(s).Run(); return dep.Run(s) }\n"})
	out, err := api.Diff(filepath.Join(oldDir, "a.go"), filepath.Join(newDir, "a.go"))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if f := findFunc(t, out, "F"); f.RiskScore < models.RiskScoreHigh {
		t.Errorf("F: risk %d (%s); want >= %d", f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
	}
}
