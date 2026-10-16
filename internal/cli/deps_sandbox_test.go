package cli

import (
	"os"
	"slices"
	"testing"
)

// RunDepsDiff runs the deps diff worker in the sandbox unless told not to,
// and returns once the sandbox has run: the worker's output is the result.
func TestRunDepsDiff_Sandboxed(t *testing.T) {
	spec := fakeRunsc(t, 0)
	oldDir, newDir := t.TempDir(), t.TempDir()

	// The fake sandbox succeeds and prints nothing. Running the analysis
	// here as well would fail: neither directory holds a module.
	if err := RunDepsDiff(oldDir, newDir, false); err != nil {
		t.Fatalf("sandboxed deps diff: %v", err)
	}
	args, mounts := sandboxSpec(t, spec)
	if !slices.Contains(args, "deps-diff") {
		t.Errorf("worker args = %v; want the deps-diff worker", args)
	}
	for _, dir := range []string{oldDir, newDir} {
		if !slices.Contains(mounts, dir) {
			t.Errorf("mounts = %v; want %s mounted", mounts, dir)
		}
	}

	// --no-sandbox runs the analysis here, which fails on the empty
	// directories, and starts no sandbox.
	if err := os.Remove(spec); err != nil {
		t.Fatal(err)
	}
	if err := RunDepsDiff(oldDir, newDir, true); err == nil {
		t.Error("unsandboxed deps diff of two empty directories succeeded; want the analysis's error")
	}
	if _, err := os.Stat(spec); !os.IsNotExist(err) {
		t.Errorf("--no-sandbox started the sandbox (spec: %v)", err)
	}
}
