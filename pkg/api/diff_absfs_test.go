package api_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// absFailFS is the disk, except that Abs fails, returning an absolute path
// that is not the file's: the value of a failed Abs is not used.
type absFailFS struct{ api.RealFileSystem }

func (absFailFS) Abs(string) (string, error) {
	return "/abs/unavailable.go", errors.New("abs unavailable")
}

// identityAbsFS is the disk, except that Abs returns the path unchanged (as
// internal/cli's MockFileSystem does).
type identityAbsFS struct{ api.RealFileSystem }

func (identityAbsFS) Abs(p string) (string, error) { return p, nil }

// DiffWithFS filters the loaded functions by the file's absolute path, as
// the loader reports it. A FileSystem whose Abs fails or returns a relative
// path falls back to filepath.Abs, so the filter still finds the file's
// functions: Handle is added, high-risk.
func TestDiffWithFS_RelativeAbs(t *testing.T) {
	root := t.TempDir()
	writeFilesIn(t, root, map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n",
		"p/a.go": "package p\n\nimport \"os/exec\"\n\nfunc Handle(s string) { exec.Command(s).Run() }\n",
	})
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, filepath.Join(root, "p", "a.go"))
	if err != nil {
		t.Fatal(err)
	}
	for name, fsys := range map[string]api.FileSystem{
		"Abs fails":                      absFailFS{},
		"Abs returns the path unchanged": identityAbsFS{},
		"control: RealFileSystem":        api.RealFileSystem{},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := api.DiffWithFS(fsys, "", rel)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, f := range out.Functions {
				names = append(names, f.Function+":"+f.Status)
			}
			if !slices.Contains(names, "Handle:"+models.StatusAdded) || out.Summary.HighRiskChanges != 1 {
				t.Errorf("functions %v, %d high-risk changes; want Handle added as the one high-risk change", names, out.Summary.HighRiskChanges)
			}
		})
	}
}
