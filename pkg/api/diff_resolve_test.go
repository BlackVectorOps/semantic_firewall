package api_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// dirFS is the disk below dir: relative names are read from dir, and Abs
// joins them to dir, wherever the working directory is.
type dirFS struct {
	api.RealFileSystem
	dir string
}

func (f dirFS) Stat(name string) (os.FileInfo, error) { return os.Stat(filepath.Join(f.dir, name)) }
func (f dirFS) ReadFile(name string) ([]byte, error)  { return os.ReadFile(filepath.Join(f.dir, name)) }
func (f dirFS) Abs(name string) (string, error)       { return filepath.Join(f.dir, name), nil }

// unresolvedFS is dirFS whose Abs fails.
type unresolvedFS struct{ dirFS }

func (unresolvedFS) Abs(name string) (string, error) { return absFailFS{}.Abs(name) }

// The FileSystem's absolute path is the one loaded: a file it places in a
// module loads with its sibling package, though the working directory is
// elsewhere.
func TestDiffWithFS_UsesTheFileSystemsAbs(t *testing.T) {
	dir := t.TempDir()
	writeFilesIn(t, dir, map[string]string{
		"go.mod":   "module example.com/m\n\ngo 1.22\n",
		"q/q.go":   "package q\n\nimport \"os/exec\"\n\nfunc Run(s string) error { return exec.Command(s).Run() }\n",
		"p/a.go":   "package p\n\nimport \"example.com/m/q\"\n\nfunc Handle(s string) error { return q.Run(s) }\n",
		"p/doc.go": "package p\n",
	})
	t.Chdir(t.TempDir())
	out, err := api.DiffWithFS(dirFS{dir: dir}, "", "p/a.go")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range out.Functions {
		names = append(names, f.Function+":"+f.Status)
	}
	if !slices.Contains(names, "Handle:"+models.StatusAdded) {
		t.Errorf("functions %v; want Handle added", names)
	}
}

// A path that neither the FileSystem nor the working directory can make
// absolute fails the diff, alone or in a batch, with an error naming it.
// The loader reports functions under absolute paths, so an unresolved path
// must not reach it: here the loader would also fail, on the same missing
// working directory, but with an error that names no file.
func TestDiff_UnresolvablePathFails(t *testing.T) {
	dir := t.TempDir()
	writeFilesIn(t, dir, map[string]string{
		"a.go": "package p\n\nimport \"os/exec\"\n\nfunc Handle(s string) { exec.Command(s).Run() }\n",
	})
	wd := filepath.Join(t.TempDir(), "wd")
	if err := os.Mkdir(wd, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(wd)
	if err := os.Remove(wd); err != nil {
		t.Fatal(err)
	}
	if abs, err := filepath.Abs("a.go"); err == nil {
		t.Skipf("the deleted working directory still resolves a.go to %s", abs)
	}
	fsys := unresolvedFS{dirFS{dir: dir}}
	if out, err := api.DiffWithFS(fsys, "", "a.go"); err == nil || !strings.Contains(err.Error(), "failed to resolve a.go") {
		t.Errorf("DiffWithFS: %+v, error %v; want the path's resolution error", out, err)
	}
	out := api.DiffBatchWithFS(fsys, []api.DiffPair{{New: "a.go"}})
	if len(out) != 1 || !strings.Contains(out[0].ErrorMessage, "failed to resolve a.go") || len(out[0].Functions) != 0 {
		t.Errorf("DiffBatchWithFS: %q %d; want the path's resolution error and no functions", out[0].ErrorMessage, len(out[0].Functions))
	}
}
