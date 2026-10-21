package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// quietStdout sends os.Stdout to the null device until the test ends.
func quietStdout(t *testing.T) {
	t.Helper()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = null
	t.Cleanup(func() { os.Stdout = stdout; null.Close() })
}

func looseGoFile(t *testing.T) (dir, file string) {
	t.Helper()
	dir = t.TempDir()
	file = filepath.Join(dir, "a.go")
	if err := os.WriteFile(file, []byte("package p\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if root := findContextRoot(file); root != "" {
		t.Skipf("%s has a context root %s above the temp dir", file, root)
	}
	return dir, file
}

// sfw diff runs the diff worker in the sandbox on both paths, mounting the
// inputs that exist; with --no-sandbox it runs no sandbox.
func TestRunDiff_Sandbox(t *testing.T) {
	dir, file := looseGoFile(t)
	missing := filepath.Join(dir, "gone.go")
	spec := fakeRunsc(t, 0)
	if err := RunDiff(missing, file, false); err != nil {
		t.Fatal(err)
	}
	args, mounts := sandboxSpec(t, spec)
	if want := []string{"internal-worker", "diff", missing, file}; len(args) < 4 || !reflect.DeepEqual(args[len(args)-4:], want) {
		t.Errorf("worker args %q; want them to end %q", args, want)
	}
	if !slices.Contains(mounts, file) || slices.Contains(mounts, missing) {
		t.Errorf("mounts %q; want %s and not the missing %s", mounts, file, missing)
	}

	if err := os.Remove(spec); err != nil {
		t.Fatal(err)
	}
	quietStdout(t)
	if err := RunDiff(missing, file, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spec); err == nil {
		t.Error("--no-sandbox ran the sandbox")
	}
}

// A sandbox that fails fails the command.
func TestRunDiff_SandboxFails(t *testing.T) {
	_, file := looseGoFile(t)
	fakeRunsc(t, 3)
	quietStdout(t)
	if err := RunDiff(file, file, false); err == nil || !strings.Contains(err.Error(), "failed to run sandboxed process") {
		t.Errorf("error %v; want the sandbox's failure", err)
	}
	if err := RunDiffBatch(writePairs(t, file+"\x00"+file+"\x00"), false, false); err == nil || !strings.Contains(err.Error(), "failed to run sandboxed process") {
		t.Errorf("batch error %v; want the sandbox's failure", err)
	}
}

// sfw diff --batch runs the batch worker in the sandbox on the pairs file,
// with batchMounts' mounts; a pairs file it cannot read fails before the
// sandbox; with --no-sandbox it runs no sandbox.
func TestRunDiffBatch_Sandbox(t *testing.T) {
	dir, file := looseGoFile(t)
	pairs := writePairs(t, filepath.Join(dir, "gone.go")+"\x00"+file+"\x00")
	spec := fakeRunsc(t, 0)
	if err := RunDiffBatch(pairs, false, false); err != nil {
		t.Fatal(err)
	}
	args, mounts := sandboxSpec(t, spec)
	if want := []string{"internal-worker", "diff-batch", pairs}; len(args) < 3 || !reflect.DeepEqual(args[len(args)-3:], want) {
		t.Errorf("worker args %q; want them to end %q", args, want)
	}
	if !slices.Contains(mounts, pairs) || !slices.Contains(mounts, file) {
		t.Errorf("mounts %q; want the pairs file and %s", mounts, file)
	}

	// --non-go reaches the worker.
	if err := RunDiffBatch(pairs, false, true); err != nil {
		t.Fatal(err)
	}
	args, _ = sandboxSpec(t, spec)
	if want := []string{"internal-worker", "diff-batch", pairs, "--non-go"}; len(args) < 4 || !reflect.DeepEqual(args[len(args)-4:], want) {
		t.Errorf("worker args %q; want them to end %q", args, want)
	}

	if err := os.Remove(spec); err != nil {
		t.Fatal(err)
	}
	if err := RunDiffBatch(writePairs(t, file), false, false); err == nil || !strings.Contains(err.Error(), "not NUL-terminated") {
		t.Errorf("malformed pairs file: %v; want its error", err)
	}
	quietStdout(t)
	if err := RunDiffBatch(pairs, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spec); err == nil {
		t.Error("a malformed pairs file or --no-sandbox ran the sandbox")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// The JSON is indented by two spaces; a diff that fails, a pairs file that
// cannot be read and a writer that fails are errors.
func TestDiffLogic_OutputAndErrors(t *testing.T) {
	dir, file := looseGoFile(t)
	var single bytes.Buffer
	if err := RunDiffLogic(RealFileSystem{}, &single, "", file); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(single.String(), "{\n  \"old_file\"") {
		t.Errorf("sfw diff output starts %.40q; want two-space indentation", single.String())
	}
	var failed bytes.Buffer
	if err := RunDiffLogic(RealFileSystem{}, &failed, dir, file); err == nil || failed.Len() != 0 {
		t.Errorf("diff of a directory: error %v, output %q; want an error and no output", err, failed.String())
	}
	if err := RunDiffLogic(RealFileSystem{}, failingWriter{}, "", file); err == nil {
		t.Error("a failing writer: no error")
	}

	pairs := writePairs(t, "\x00"+file+"\x00")
	var batch bytes.Buffer
	if err := RunDiffBatchLogic(RealFileSystem{}, &batch, pairs, false); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(batch.String(), "[\n  {\n    \"old_file\"") {
		t.Errorf("sfw diff --batch output starts %.40q; want two-space indentation", batch.String())
	}
	var malformed bytes.Buffer
	if err := RunDiffBatchLogic(RealFileSystem{}, &malformed, writePairs(t, file), false); err == nil || malformed.Len() != 0 {
		t.Errorf("malformed pairs file: error %v, output %q; want an error and no output", err, malformed.String())
	}
	if err := RunDiffBatchLogic(RealFileSystem{}, failingWriter{}, pairs, false); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("a failing writer: %v; want its error", err)
	}
}
