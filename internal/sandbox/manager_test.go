package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateSpec verifies that the OCI spec is generated correctly with valid inputs
// and required security constraints. It mocks the GOROOT resolution to ensure
// deterministic build environments.
func TestGenerateSpec(t *testing.T) {
	// Mocks the external "go" command to return a fixed GOROOT.
	// This ensures the test passes even if Go isn't installed in the CI environment.
	// FIX: Use t.TempDir() to create a real directory. manager.go checks os.Stat(goroot),
	// so a non-existent path like "/usr/local/go-mock" would be skipped, failing the test.
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
