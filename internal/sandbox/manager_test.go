// -- internal/sandbox/manager_test.go --
package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestGenerateSpec verifies that the OCI spec is generated correctly with valid inputs
// and required security constraints. It mocks the GOROOT resolution to ensure
// deterministic build environments regardless of the host state.
func TestGenerateSpec(t *testing.T) {
	// Mocks the external "go" command to return a fixed GOROOT.
	// This ensures the test passes even if Go isn't installed in the CI environment.
	// Uses t.TempDir() to create a real directory to satisfy os.Stat checks in the manager.
	mockGoroot := t.TempDir()

	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		// Intercepts "go env GOROOT"
		if cmd == "go" && len(args) > 0 && args[0] == "env" {
			return mockHelperCommand(ctx, "echo", mockGoroot)
		}
		return mockHelperCommand(ctx, "false") // Fail on unexpected calls
	})
	defer restoreExec()

	// Setup temporary workdir for absolute path resolution
	tmpDir := t.TempDir()
	selfExe := "/bin/mock_sfw"

	cfg := Config{
		Args:    []string{"check", "--verbose"},
		Mounts:  []string{tmpDir},
		WorkDir: tmpDir,
	}

	// Execute with context
	spec, err := generateSpec(context.Background(), cfg, selfExe)
	if err != nil {
		t.Fatalf("generateSpec failed: %v", err)
	}

	// Verification 1: Process Arguments (prepended with binary path)
	if len(spec.Process.Args) != 3 {
		t.Errorf("len(Process.Args) = %d, want 3", len(spec.Process.Args))
	}
	if spec.Process.Args[0] != "/app/sfw" {
		t.Errorf("Process.Args[0] = %s, want /app/sfw", spec.Process.Args[0])
	}
	if spec.Process.Args[1] != "check" {
		t.Errorf("Process.Args[1] = %s, want check", spec.Process.Args[1])
	}

	// Verification 2: Env Var (Correct ID)
	foundEnv := false
	for _, e := range spec.Process.Env {
		if strings.HasPrefix(e, EnvSandboxID+"=") {
			foundEnv = true
			break
		}
	}
	if !foundEnv {
		t.Errorf("Environment variable %s missing from spec", EnvSandboxID)
	}

	// Verification 3: Mounts
	foundUserMount := false
	foundGorootMount := false
	for _, m := range spec.Mounts {
		if m.Source == tmpDir && m.Destination == tmpDir {
			foundUserMount = true
		}
		if m.Source == mockGoroot && m.Destination == mockGoroot {
			foundGorootMount = true
		}
	}
	if !foundUserMount {
		t.Errorf("User mount %s not found in spec mounts", tmpDir)
	}
	// This confirms resolveSystemGoroot successfully used our mock
	if !foundGorootMount {
		t.Errorf("System GOROOT mount %s not found (mock injection failed)", mockGoroot)
	}
}

// TestGenerateSpec_MountSorting ensures that overlapping mounts are sorted correctly.
// A parent directory must always be mounted BEFORE its subdirectory to avoid shadowing.
func TestGenerateSpec_MountSorting(t *testing.T) {
	// Create paths
	rootDir := t.TempDir()
	childDir := filepath.Join(rootDir, "child")
	if err := os.Mkdir(childDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Mount child FIRST, then root.
	// If NOT sorted, child comes first. Root shadows child. Failure.
	// If sorted, Root comes first. Child overlays Root. Success.
	cfg := Config{
		Args:    []string{"noop"},
		Mounts:  []string{childDir, rootDir},
		WorkDir: rootDir,
	}

	// Mock deps
	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		return mockHelperCommand(ctx, "echo", "")
	})
	defer restoreExec()
	origLookPath := lookPathFunc
	lookPathFunc = func(file string) (string, error) { return "/bin/true", nil }
	defer func() { lookPathFunc = origLookPath }()

	spec, err := generateSpec(context.Background(), cfg, "/bin/mock")
	if err != nil {
		t.Fatalf("generateSpec failed: %v", err)
	}

	// Find the indices of the mounts
	rootIdx, childIdx := -1, -1
	for i, m := range spec.Mounts {
		if m.Destination == rootDir {
			rootIdx = i
		}
		if m.Destination == childDir {
			childIdx = i
		}
	}

	if rootIdx == -1 || childIdx == -1 {
		t.Fatal("Failed to find requested mounts in spec")
	}

	// Assert: Root must be mounted BEFORE Child
	if rootIdx > childIdx {
		t.Errorf("Mount Order Bug: Parent %s (idx %d) is mounted AFTER Child %s (idx %d). This causes shadowing.",
			rootDir, rootIdx, childDir, childIdx)
	}
}

// TestGenerateSpec_SecurityOptions ensures that critical filesystems are mounted
// without restrictive flags that would break runtime functionality.
// Incorrect flags here often lead to obscure "permission denied" errors deep in the runtime.
func TestGenerateSpec_SecurityOptions(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Args:    []string{"check"},
		WorkDir: "/tmp",
	}
	selfExe := "/bin/mock_sfw"

	// Mock dependencies using the local helper logic for consistency
	// We override lookPathFunc to ensure we don't depend on the host PATH
	origLookPath := lookPathFunc
	lookPathFunc = func(file string) (string, error) { return "/bin/true", nil }
	defer func() { lookPathFunc = origLookPath }()

	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		return mockHelperCommand(ctx, "true")
	})
	defer restoreExec()

	spec, err := generateSpec(ctx, cfg, selfExe)
	if err != nil {
		t.Fatalf("generateSpec failed: %v", err)
	}

	findMount := func(dest string) *Mount {
		for _, m := range spec.Mounts {
			if m.Destination == dest {
				return &m
			}
		}
		return nil
	}

	// 1. Verify /proc does NOT have 'noexec'
	// gVisor and other runtimes need to execute internal trampolines or read procfs in specific ways
	// that can be blocked by aggressive mount options.
	procMount := findMount("/proc")
	if procMount == nil {
		t.Fatal("/proc mount missing")
	}
	if slices.Contains(procMount.Options, "noexec") {
		t.Errorf("Security Regression: /proc mounted with 'noexec'. This causes fork/exec permission denied errors in gVisor.")
	}

	// 2. Verify /tmp does NOT have 'noexec'
	// Users often use /tmp for intermediate build artifacts or script execution.
	tmpMount := findMount("/tmp")
	if tmpMount == nil {
		t.Fatal("/tmp mount missing")
	}
	if slices.Contains(tmpMount.Options, "noexec") {
		t.Errorf("Operational Restriction: /tmp mounted with 'noexec'. Prevents execution of temporary binaries.")
	}
}

// TestRun_Orchestration simulates the full sandbox lifecycle without invoking runsc.
// It verifies that bundle creation, config generation, and command arguments are correct.
func TestRun_Orchestration(t *testing.T) {
	// 1. Mock LookPath to pretend 'runsc' exists.
	origLookPath := lookPathFunc
	lookPathFunc = func(file string) (string, error) {
		return "/usr/bin/runsc", nil
	}
	defer func() { lookPathFunc = origLookPath }()

	// 2. Mock Exec to intercept the final 'runsc run' call.
	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		// Handles the "go env" call inside generateSpec
		if cmd == "go" {
			return mockHelperCommand(ctx, "echo", "")
		}

		// Handles the actual runtime execution
		// We verify the arguments passed to the OCI runtime here
		if cmd == "/usr/bin/runsc" {
			// Check for critical security flags
			argsStr := strings.Join(args, " ")
			if !strings.Contains(argsStr, "--rootless") {
				t.Error("Missing --rootless flag in runtime args")
			}
			if !strings.Contains(argsStr, "--network=none") {
				t.Error("Missing --network=none flag in runtime args")
			}
			return mockHelperCommand(ctx, "true") // Return exit code 0
		}
		return mockHelperCommand(ctx, "false")
	})
	defer restoreExec()

	// Setup
	cfg := Config{
		Args:    []string{"worker"},
		WorkDir: t.TempDir(),
	}

	// Execute
	// We use io.Discard because we don't care about the output for this specific test
	err := Run(context.Background(), cfg, os.Stdout, os.Stderr)
	if err != nil {
		t.Fatalf("Run() failed during orchestration: %v", err)
	}
}

// TestRunErrors verifies that process failure returns a handled error rather than
// crashing the parent or exiting cleanly. Vital for stability when the sandbox
// encounters runtime faults.
func TestRunErrors(t *testing.T) {
	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		// Simulate a hard failure in the runtime
		return mockHelperCommand(ctx, "false")
	})
	defer restoreExec()

	origLookPath := lookPathFunc
	lookPathFunc = func(file string) (string, error) {
		return "/usr/bin/false", nil
	}
	defer func() { lookPathFunc = origLookPath }()

	ctx := context.Background()
	cfg := Config{Args: []string{"noop"}, WorkDir: "/tmp"}

	err := Run(ctx, cfg, io.Discard, io.Discard)

	if err == nil {
		t.Errorf("Expected an error from failing subprocess, got nil")
	}
}

// TestPrepareMountPoints ensures that the function creates necessary directories/files
// in the rootfs to prevent bind mount failures.
func TestPrepareMountPoints(t *testing.T) {
	rootfs := t.TempDir()
	sourceDir := t.TempDir()
	sourceFile := filepath.Join(sourceDir, "file.txt")
	if err := os.WriteFile(sourceFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	mounts := []Mount{
		{Destination: "/mnt/dir", Type: "bind", Source: sourceDir},
		{Destination: "/mnt/file", Type: "bind", Source: sourceFile},
		// Proc is a virtual FS, so we don't need source validation in the test
		// but the function should create the mount point.
		{Destination: "/proc", Type: "proc"},
	}

	if err := prepareMountPoints(rootfs, mounts); err != nil {
		t.Fatalf("prepareMountPoints failed: %v", err)
	}

	// Verify Directory created
	if fi, err := os.Stat(filepath.Join(rootfs, "mnt/dir")); err != nil || !fi.IsDir() {
		t.Error("Failed to create mount point directory")
	}

	// Verify File created
	if fi, err := os.Stat(filepath.Join(rootfs, "mnt/file")); err != nil || fi.IsDir() {
		t.Error("Failed to create mount point file")
	}
}

// TestPrepareMountPoints_Permissions verifies that mounts are created executable.
// If the bind mount stub loses the executable bit (0111), the runtime will throw
// permission denied before we even enter the sandbox.
func TestPrepareMountPoints_Permissions(t *testing.T) {
	tmpDir := t.TempDir()

	// Use the test binary itself as a source since we know it exists
	mounts := []Mount{{Destination: "/app/exe", Type: "bind", Source: os.Args[0]}}

	if err := prepareMountPoints(tmpDir, mounts); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(filepath.Join(tmpDir, "/app/exe"))
	if err != nil {
		t.Fatal(err)
	}
	// Check for executable bit (0111)
	if fi.Mode()&0111 == 0 {
		t.Errorf("Mount stub is not executable: %v. This will block binary execution inside the container.", fi.Mode())
	}
}

// TestIsSandboxed verifies the environment variable check logic.
func TestIsSandboxed(t *testing.T) {
	// Ensure clean state
	orig := os.Getenv(EnvSandboxID)
	defer os.Setenv(EnvSandboxID, orig)

	os.Unsetenv(EnvSandboxID)
	if IsSandboxed() {
		t.Error("IsSandboxed() = true, want false when env var is missing")
	}

	os.Setenv(EnvSandboxID, "1")
	if !IsSandboxed() {
		t.Error("IsSandboxed() = false, want true when env var is set")
	}
}

// -- Test Helpers --

// replaceExecFunc swaps the internal execCmdFunc with a mock and returns a teardown function.
func replaceExecFunc(mock func(context.Context, string, ...string) *exec.Cmd) func() {
	orig := execCmdFunc
	execCmdFunc = mock
	return func() {
		execCmdFunc = orig
	}
}

// mockHelperCommand creates a command that re-runs the test binary as a helper process.
// This is the standard Go pattern for mocking exec.Command.
func mockHelperCommand(ctx context.Context, command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

// TestHelperProcess is not a real test. It is used by mockHelperCommand to simulate
// a subprocess. It mimics the behavior of the mocked commands (echo, true, false).
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	// Skip flags parsed by the test runner to get to the actual command
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	if len(args) == 0 {
		os.Exit(0)
	}

	cmd, cmdArgs := args[0], args[1:]
	switch cmd {
	case "echo":
		fmt.Print(strings.Join(cmdArgs, " "))
	case "true":
		os.Exit(0)
	case "false":
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "TestHelperProcess: unknown command %q\n", cmd)
		os.Exit(2)
	}
	os.Exit(0)
}
