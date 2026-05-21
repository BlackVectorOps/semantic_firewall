package api_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
)

// TestShortFunctionName covers the cases that used to live in
// internal/cli's test suite, pinning the moved implementation against
// regressions.
func TestShortFunctionName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"fmt.Println", "Println"},
		{"main.main", "main"},
		{"github.com/user/repo/pkg.Func", "Func"},
		{"pkg.(*Type).Method", "(*Type).Method"},
		{"(*pkg.Type).Method", "(*Type).Method"},
		{"pkg.Func[int]", "Func[int]"},
		{"pkg.Func[a/b.T]", "Func[a/b.T]"},
		{"pkg.Type[sub.T].Method", "Type[sub.T].Method"},
		{"Type[sub.T].Method", "Type[sub.T].Method"},
	}
	for _, tc := range cases {
		if got := api.ShortFunctionName(tc.in); got != tc.want {
			t.Errorf("ShortFunctionName(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

const srcA = `package x

func Add(a, b int) int {
	return a + b
}
`

const srcB = `package x

func Add(a, b int) int {
	if a < 0 {
		return -1
	}
	return a + b
}
`

// TestDiff_DetectsModification exercises the public Diff entry point
// on real files, confirming the wiring (RealFileSystem, SSA build,
// topology match, summary aggregation) survives the move out of
// internal/cli.
func TestDiff_DetectsModification(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "a.go")
	newPath := filepath.Join(dir, "b.go")
	if err := os.WriteFile(oldPath, []byte(srcA), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(newPath, []byte(srcB), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	out, err := api.Diff(oldPath, newPath)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if out.OldFile != oldPath || out.NewFile != newPath {
		t.Errorf("paths not echoed: %+v", out)
	}
	if out.Summary.TotalFunctions == 0 {
		t.Fatal("expected at least one function")
	}

	var found bool
	for _, f := range out.Functions {
		if f.Function == "Add" {
			found = true
			if f.Status != models.StatusModified {
				t.Errorf("Add status = %q; want modified", f.Status)
			}
		}
	}
	if !found {
		t.Fatal("Add not present in diff output")
	}
}

// TestDiff_MissingFileTreatedAsEmpty verifies that an absent path is
// interpreted as "no functions" (the added/removed-file case) rather
// than an error, which the GitHub Action depends on when one side of
// the diff doesn't exist yet.
func TestDiff_MissingFileTreatedAsEmpty(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.go")
	missing := filepath.Join(dir, "missing.go")
	if err := os.WriteFile(present, []byte(srcA), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, err := api.Diff(missing, present)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if out.Summary.Added == 0 {
		t.Errorf("expected added > 0 when old side missing; got %+v", out.Summary)
	}
}
