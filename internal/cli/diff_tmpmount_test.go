package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// Files kept directly in /tmp (a common place for two versions of a file
// diffed ad hoc) have no context root. /tmp is a reserved sandbox path (a
// fresh tmpfs) that cannot be mounted, so a batch mounts such files
// themselves, as a single sandboxed `sfw diff` does.
//
// the sandboxed batch runs like the single diff of the
// same pair (the fake runsc succeeds, so RunDiffBatch returns nil).
func TestRunDiffBatch_SandboxedFilesDirectlyInTmp(t *testing.T) {
	fakeRunsc(t, 0)
	write := func(pattern, src string) string {
		f, err := os.CreateTemp("/tmp", pattern)
		if err != nil {
			t.Skipf("cannot write to /tmp: %v", err)
		}
		t.Cleanup(func() { os.Remove(f.Name()) })
		if _, err := f.WriteString(src); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return f.Name()
	}
	oldFile := write("sfw-old-*.go", "package p\n\nfunc A() int { return 1 }\n")
	newFile := write("sfw-new-*.go", "package p\n\nfunc A() int { return 2 }\n")
	if root := findContextRoot(oldFile); root != "" {
		t.Skipf("%s has a context root %s", oldFile, root)
	}
	if filepath.Dir(oldFile) != "/tmp" {
		t.Skipf("temp file %s is not directly in /tmp", oldFile)
	}

	// Control: the single sandboxed diff of the same files runs.
	if err := RunDiff(oldFile, newFile, false); err != nil {
		t.Fatalf("control: sandboxed single diff: %v", err)
	}
	pairs := writePairs(t, oldFile+"\x00"+newFile+"\x00")
	if err := RunDiffBatch(pairs, false); err != nil {
		t.Errorf("sandboxed batch of the same pair: %v; want it to run like the single diff", err)
	}
}
