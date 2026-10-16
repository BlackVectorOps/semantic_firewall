package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/internal/sandbox"
)

// These tests run the built sfw, since main's routing, flag defaults and
// exit codes exist only there.

// buildSFW builds this package's binary into a temporary directory.
func buildSFW(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the sfw binary")
	}
	bin := filepath.Join(t.TempDir(), "sfw")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// runSFW runs bin with args and env added to this process's environment,
// with the type cache off unless env sets it, and returns its output and
// exit code.
func runSFW(t *testing.T, bin string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), sandbox.EnvSandboxID+"=", "SFW_TYPE_CACHE=off")
	cmd.Env = append(cmd.Env, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatalf("running sfw: %v", err)
	}
	return out.String(), errOut.String(), code
}

// fakeRunscPath returns a PATH entry holding a "runsc" that saves the OCI
// spec it is given to the returned path and exits 0 without running
// anything.
func fakeRunscPath(t *testing.T) (pathEnv, spec string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	dir := t.TempDir()
	spec = filepath.Join(dir, "spec.json")
	script := fmt.Sprintf("#!/bin/sh\nwhile [ $# -gt 0 ]; do\n\tif [ \"$1\" = --bundle ]; then cp \"$2/config.json\" %q; fi\n\tshift\ndone\nexit 0\n", spec)
	if err := os.WriteFile(filepath.Join(dir, sandbox.RuntimeBinary), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return "PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), spec
}

// writeModule writes a module with one file and returns the file's path.
func writeModule(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "a.go")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// `sfw deps diff` runs in the sandbox by default and outside it with
// --no-sandbox.
func TestMain_DepsDiffSandboxedByDefault(t *testing.T) {
	bin := buildSFW(t)
	pathEnv, spec := fakeRunscPath(t)
	oldDir, newDir := t.TempDir(), t.TempDir()

	if _, stderr, code := runSFW(t, bin, []string{pathEnv}, "deps", "diff", oldDir, newDir); code != 0 {
		t.Fatalf("sandboxed deps diff exited %d: %s", code, stderr)
	}
	data, err := os.ReadFile(spec)
	if err != nil {
		t.Fatalf("deps diff did not start the sandbox: %v", err)
	}
	var s struct{ Process struct{ Args []string } }
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.Process.Args, "deps-diff") {
		t.Errorf("sandbox args = %v; want the deps-diff worker", s.Process.Args)
	}

	if err := os.Remove(spec); err != nil {
		t.Fatal(err)
	}
	// Unsandboxed, the analysis runs here and fails on the empty directories.
	if _, _, code := runSFW(t, bin, []string{pathEnv}, "deps", "diff", "--no-sandbox", oldDir, newDir); code == 0 {
		t.Error("unsandboxed deps diff of two empty directories exited 0")
	}
	if _, err := os.Stat(spec); !os.IsNotExist(err) {
		t.Errorf("deps diff --no-sandbox started the sandbox (spec: %v)", err)
	}
}

// A failing batch fails the command: the Action's diff mode runs one batch,
// and a batch that errors must not read as a clean diff.
func TestMain_DiffBatchFailureExitsNonZero(t *testing.T) {
	bin := buildSFW(t)
	missing := filepath.Join(t.TempDir(), "no-such-pairs")
	stdout, stderr, code := runSFW(t, bin, nil, "diff", "--no-sandbox", "--batch", missing)
	if code == 0 {
		t.Errorf("sfw diff --batch with a missing pairs file exited 0\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

// Two files without --batch are a single diff.
func TestMain_DiffTwoFiles(t *testing.T) {
	bin := buildSFW(t)
	file := writeModule(t, "package p\n\nfunc A() int { return 1 }\n")
	stdout, stderr, code := runSFW(t, bin, nil, "diff", "--no-sandbox", file, file)
	if code != 0 {
		t.Fatalf("sfw diff exited %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"functions"`) {
		t.Errorf("sfw diff printed %q; want a diff result", stdout)
	}
}

// main decides the type cache setting before any command runs:
// SFW_TYPE_CACHE=on becomes a writable cache under the user cache
// directory, which a diff then fills.
func TestMain_ConfiguresTypeCache(t *testing.T) {
	bin := buildSFW(t)
	cacheHome := t.TempDir()
	file := writeModule(t, "package p\n\nimport \"strings\"\n\nfunc A(s string) string { return strings.ToUpper(s) }\n")
	env := []string{"SFW_TYPE_CACHE=on", "XDG_CACHE_HOME=" + cacheHome}
	if _, stderr, code := runSFW(t, bin, env, "diff", "--no-sandbox", file, file); code != 0 {
		t.Fatalf("sfw diff exited %d: %s", code, stderr)
	}
	entries := 0
	err := filepath.WalkDir(filepath.Join(cacheHome, "sfw", "types"), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			entries++
		}
		return nil
	})
	if err != nil || entries == 0 {
		t.Errorf("type cache under %s: %d entries, %v; want the diff's dependencies stored", cacheHome, entries, err)
	}
}
