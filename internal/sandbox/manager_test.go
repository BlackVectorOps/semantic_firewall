// -- internal/sandbox/manager_test.go --
package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestGenerateSpec verifies that the OCI spec is generated correctly with valid inputs
// and required security constraints. It mocks the GOROOT resolution to ensure
// deterministic build environments regardless of the host state.
func TestGenerateSpec(t *testing.T) {
	// Mocks the external "go" command to return a fixed GOROOT.
	// This ensures the test passes even if Go isn't installed in the CI environment.
	// Uses t.TempDir() to create a real directory to satisfy os.Stat checks in the manager.
	mockGoroot := t.TempDir()

	// resolveGoToolchain prefers GOROOT/GOMODCACHE from the environment over
	// `go env`; clear them so the mock below is what gets resolved. The go
	// command exports GOROOT to test binaries when it switches toolchains.
	t.Setenv("GOROOT", "")
	t.Setenv("GOMODCACHE", "")

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
	spec, err := generateSpec(context.Background(), cfg, selfExe, DefaultLimits)
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

	// Verification 4: Go caches. The module cache is mounted read-only (the
	// loader runs with GOPROXY=off); the build cache must be writable, so it
	// lives on the /tmp tmpfs rather than on a read-only host mount.
	foundModMount := false
	for _, m := range spec.Mounts {
		if m.Destination == "/gomodcache" {
			foundModMount = m.Source == mockGoroot && slices.Contains(m.Options, "ro")
		}
		if m.Destination == "/gocache" {
			t.Errorf("GOCACHE must not be a read-only bind mount: %+v", m)
		}
	}
	if !foundModMount {
		t.Errorf("read-only /gomodcache mount of %s not found", mockGoroot)
	}
	for _, want := range []string{"GOMODCACHE=/gomodcache", "GOCACHE=/tmp/gocache"} {
		if !slices.Contains(spec.Process.Env, want) {
			t.Errorf("Process.Env missing %s: %v", want, spec.Process.Env)
		}
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

	spec, err := generateSpec(context.Background(), cfg, "/bin/mock", DefaultLimits)
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

	spec, err := generateSpec(ctx, cfg, selfExe, DefaultLimits)
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
			if !strings.HasPrefix(args[0], "--root=") || !strings.HasSuffix(args[0], "/state") {
				t.Errorf("runtime args %v; want --root=<bundle>/state first", args)
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

// Under --rootless the spec's IDs are of runsc's own user namespace, where
// the caller is root: the host UID does not exist there.
func TestGenerateSpec_RootlessIDMapping(t *testing.T) {
	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		return mockHelperCommand(ctx, "true")
	})
	defer restoreExec()

	spec, err := generateSpec(context.Background(), Config{WorkDir: "/tmp"}, "/bin/mock_sfw", DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := []IDMapping{{ContainerID: 0, HostID: 0, Size: 1}}
	if !slices.Equal(spec.Linux.UIDMappings, want) || !slices.Equal(spec.Linux.GIDMappings, want) {
		t.Errorf("mappings uid %v gid %v; want %v", spec.Linux.UIDMappings, spec.Linux.GIDMappings, want)
	}
}

// The spec bounds each process with rlimits the sentry enforces and caps
// /tmp, and carries no cgroup resources, which --ignore-cgroups would drop.
func TestGenerateSpec_Limits(t *testing.T) {
	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		return mockHelperCommand(ctx, "true")
	})
	defer restoreExec()

	l := Limits{Timeout: time.Minute, MemoryMiB: 4096, TmpMiB: 512}
	spec, err := generateSpec(context.Background(), Config{WorkDir: "/tmp"}, "/bin/mock_sfw", l)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Rlimit{}
	for _, r := range spec.Process.Rlimits {
		got[r.Type] = r
	}
	for typ, want := range map[string]uint64{
		"RLIMIT_AS":    4096 << 20,
		"RLIMIT_FSIZE": 512 << 20,
		"RLIMIT_CPU":   61 * uint64(runtime.NumCPU()),
	} {
		if r := got[typ]; r.Soft != want || r.Hard != want {
			t.Errorf("%s = %d/%d; want %d/%d", typ, r.Soft, r.Hard, want, want)
		}
	}
	for _, m := range spec.Mounts {
		if m.Destination == "/tmp" && !slices.Contains(m.Options, "size=512m") {
			t.Errorf("/tmp options %v; want size=512m", m.Options)
		}
	}
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"resources"`) {
		t.Error("spec carries cgroup resources")
	}
}

// The default address space is three quarters of the host's memory.
func TestDefaultMemoryMiB(t *testing.T) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Skip("no /proc/meminfo")
	}
	var kib uint64
	fmt.Sscanf(strings.SplitN(string(data), "\n", 2)[0], "MemTotal: %d kB", &kib)
	if want := max(kib/1024*3/4, minMemoryMiB); kib == 0 || DefaultLimits.MemoryMiB != want {
		t.Errorf("default memory %d MiB; want %d (MemTotal %d kB)", DefaultLimits.MemoryMiB, want, kib)
	}
}

func TestLimitsFromEnv(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want Limits
		bad  bool
	}{
		{env: nil, want: DefaultLimits},
		{env: map[string]string{EnvTimeout: "90s", EnvMemoryMiB: "1024", EnvTmpMiB: "64"}, want: Limits{Timeout: 90 * time.Second, MemoryMiB: 1024, TmpMiB: 64}},
		{env: map[string]string{EnvMemoryMiB: "512"}, bad: true},
		{env: map[string]string{EnvTimeout: "ten"}, bad: true},
		{env: map[string]string{EnvTimeout: "0s"}, bad: true},
		{env: map[string]string{EnvMemoryMiB: "0"}, bad: true},
		{env: map[string]string{EnvTmpMiB: "-1"}, bad: true},
	} {
		for _, k := range []string{EnvTimeout, EnvMemoryMiB, EnvTmpMiB} {
			t.Setenv(k, c.env[k])
		}
		got, err := LimitsFromEnv()
		if (err != nil) != c.bad || (!c.bad && got != c.want) {
			t.Errorf("LimitsFromEnv(%v) = %+v, %v; want %+v, error %v", c.env, got, err, c.want, c.bad)
		}
	}
}

// A run past its timeout fails, and its container is killed and deleted
// through the run's own state root, so no sandbox or gofer outlives it.
func TestRun_TimeoutKillsAndDeletes(t *testing.T) {
	origLookPath := lookPathFunc
	lookPathFunc = func(string) (string, error) { return "/usr/bin/runsc", nil }
	defer func() { lookPathFunc = origLookPath }()

	var mu sync.Mutex
	var calls [][]string
	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		if cmd == "go" {
			return mockHelperCommand(ctx, "echo", "")
		}
		mu.Lock()
		calls = append(calls, args)
		mu.Unlock()
		if slices.Contains(args, "run") {
			return mockHelperCommand(ctx, "sleep")
		}
		return mockHelperCommand(ctx, "true")
	})
	defer restoreExec()
	t.Setenv(EnvTimeout, "200ms")

	start := time.Now()
	err := Run(context.Background(), Config{Args: []string{"worker"}, WorkDir: t.TempDir()}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "timed out after 200ms") {
		t.Fatalf("Run = %v; want a timeout error", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Run took %v after a 200ms timeout", d)
	}

	mu.Lock()
	defer mu.Unlock()
	var root, id string
	seen := map[string]bool{}
	for _, args := range calls {
		r := args[0]
		if !strings.HasPrefix(r, "--root=") {
			t.Fatalf("runsc %v: want --root first", args)
		}
		if root == "" {
			root = r
		} else if r != root {
			t.Errorf("runsc %v: root %s; want %s for every call", args, r, root)
		}
		switch {
		case slices.Contains(args, "run"):
			id = args[len(args)-1]
			seen["run"] = true
		case slices.Equal(args[len(args)-2:], []string{id, "KILL"}):
			seen["kill"] = true
		case slices.Equal(args[len(args)-3:], []string{"delete", "-force", id}):
			seen["delete"] = true
		}
	}
	for _, step := range []string{"run", "kill", "delete"} {
		if !seen[step] {
			t.Errorf("no runsc %s among %v", step, calls)
		}
	}
}

// A KVM device the user may not open is not used.
func TestKVMUsable(t *testing.T) {
	dir := t.TempDir()
	open, closed := filepath.Join(dir, "open"), filepath.Join(dir, "closed")
	if err := os.WriteFile(open, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(closed, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	if !kvmUsable(open) {
		t.Error("kvmUsable(rw device) = false")
	}
	if os.Getuid() != 0 && kvmUsable(closed) {
		t.Error("kvmUsable(device without access) = true")
	}
	if kvmUsable(filepath.Join(dir, "missing")) {
		t.Error("kvmUsable(missing) = true")
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
	case "sleep":
		time.Sleep(time.Minute)
	default:
		fmt.Fprintf(os.Stderr, "TestHelperProcess: unknown command %q\n", cmd)
		os.Exit(2)
	}
	os.Exit(0)
}

// The persistent type cache named by EnvTypeCache, writable or not, is
// mounted read-only and named read-only to the worker; without an
// existing absolute directory there is none; no input may take its path.
func TestGenerateSpec_TypeCache(t *testing.T) {
	restoreExec := replaceExecFunc(func(ctx context.Context, cmd string, args ...string) *exec.Cmd {
		return mockHelperCommand(ctx, "true")
	})
	defer restoreExec()
	t.Setenv("GOROOT", "")
	t.Setenv("GOMODCACHE", "")
	dir := t.TempDir()
	for setting, mounted := range map[string]bool{
		"rw:" + dir:                          true,
		"ro:" + dir:                          true,
		"off":                                false,
		"":                                   false,
		"rw:" + filepath.Join(dir, "absent"): false,
		"rw:relative":                        false,
	} {
		t.Setenv(EnvTypeCache, setting)
		spec, err := generateSpec(context.Background(), Config{Args: []string{"diff"}, WorkDir: "/tmp"}, "/bin/mock_sfw", DefaultLimits)
		if err != nil {
			t.Fatalf("%q: %v", setting, err)
		}
		var mount *Mount
		for i, m := range spec.Mounts {
			if m.Destination == typeCacheMount {
				mount = &spec.Mounts[i]
			}
		}
		wantEnv := EnvTypeCache + "=off"
		if mounted {
			wantEnv = EnvTypeCache + "=ro:" + typeCacheMount
			if mount == nil || mount.Source != dir || !slices.Contains(mount.Options, "ro") {
				t.Errorf("%q: mount %+v; want %s read-only at %s", setting, mount, dir, typeCacheMount)
			}
		} else if mount != nil {
			t.Errorf("%q: mounted %+v", setting, mount)
		}
		if !slices.Contains(spec.Process.Env, wantEnv) {
			t.Errorf("%q: env %v lacks %s", setting, spec.Process.Env, wantEnv)
		}
	}

	t.Setenv(EnvTypeCache, "rw:"+dir)
	if _, err := generateSpec(context.Background(), Config{Mounts: []string{typeCacheMount}, WorkDir: "/tmp"}, "/bin/mock_sfw", DefaultLimits); err == nil || !strings.Contains(err.Error(), "reserved sandbox path") {
		t.Errorf("an input mounted at %s: %v; want it refused as reserved", typeCacheMount, err)
	}
}
