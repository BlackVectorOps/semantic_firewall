package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/internal/sandbox"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/api"
)

// fakeRunsc puts a "runsc" that is /bin/true first on PATH, so the real
// sandbox.Run builds and validates the OCI spec for the mounts it is given
// and then "runs" successfully without starting anything.
func fakeRunsc(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true not available")
	}
	bin := t.TempDir()
	if err := os.Symlink("/bin/true", filepath.Join(bin, sandbox.RuntimeBinary)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(sandbox.EnvSandboxID, "")
}

// `diff` treats a missing input file as an empty file (README, Commands;
// api.Diff). Under the sandbox, RunDiff passes the missing path itself to
// SandboxExec as a mount, and the sandbox refuses to build a spec with a
// mount source that does not exist.
//
// the sandboxed `sfw diff missing.go new.go` runs (here
// the fake runsc succeeds, so RunDiff returns nil), as `--no-sandbox` does.
func TestRunDiff_SandboxedMissingSide(t *testing.T) {
	fakeRunsc(t)
	dir := t.TempDir()
	writeFile := func(name, src string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	writeFile("go.mod", "module example.com/m\n\ngo 1.22\n")
	newFile := writeFile("p/a.go", "package p\n\nfunc A() int { return 1 }\n")
	missing := filepath.Join(dir, "p", "missing.go")

	// Unsandboxed, the missing side is an absent file.
	if err := RunDiffLogic(RealFileSystem{}, devNullWriter{}, missing, newFile); err != nil {
		t.Fatalf("unsandboxed diff: %v", err)
	}
	// Control: with both files present the faked sandbox runs.
	if err := RunDiff(newFile, newFile, false); err != nil {
		t.Fatalf("control: sandboxed diff of two present files: %v", err)
	}
	if err := RunDiff(missing, newFile, false); err != nil {
		t.Errorf("sandboxed diff with a missing old file: %v; want it to run like --no-sandbox", err)
	}
}

// A batch pair may name a missing file as the absent side (api.DiffPair).
// batchMounts mounts the directory of an input without a context root,
// which for a missing file in a missing directory does not exist, and the
// sandbox refuses the spec, failing the whole batch.
//
// the sandboxed batch runs (the fake runsc succeeds).
func TestRunDiffBatch_SandboxedMissingSideWithoutRoot(t *testing.T) {
	fakeRunsc(t)
	dir := t.TempDir()
	newFile := filepath.Join(dir, "new", "x.go")
	if err := os.MkdirAll(filepath.Dir(newFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newFile, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if root := findContextRoot(newFile); root != "" {
		t.Skipf("%s has a context root %s above the temp dir", newFile, root)
	}
	oldFile := filepath.Join(dir, "gone", "x.go") // added file: old side missing
	pairs := writePairs(t, oldFile+"\x00"+newFile+"\x00")

	// Unsandboxed, the pair diffs fine.
	if err := RunDiffBatchLogic(RealFileSystem{}, devNullWriter{}, pairs); err != nil {
		t.Fatalf("unsandboxed batch: %v", err)
	}
	// Control: with both files present the faked sandbox runs.
	if err := RunDiffBatch(writePairs(t, newFile+"\x00"+newFile+"\x00"), false); err != nil {
		t.Fatalf("control: sandboxed batch of present files: %v", err)
	}
	t.Logf("mounts: %v", batchMounts(pairs, []api.DiffPair{{Old: oldFile, New: newFile}}))
	if err := RunDiffBatch(pairs, false); err != nil {
		t.Errorf("sandboxed batch with a missing old file: %v; want it to run like --no-sandbox", err)
	}
}

type devNullWriter struct{}

func (devNullWriter) Write(p []byte) (int, error) { return len(p), nil }
