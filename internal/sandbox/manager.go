package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// -- Internal Hooks for Testing --

// These variables allow unit tests to mock OS interactions without
// requiring the actual runsc binary or root privileges during test execution.
var (
	lookPathFunc = exec.LookPath
	execCmdFunc  = exec.CommandContext
)

// Config defines the execution parameters for the sandboxed process.
type Config struct {
	Args    []string // Arguments for the internal worker
	Mounts  []string // List of host paths to bind mount (read only)
	WorkDir string   // Working directory inside the sandbox
}

const (
	// Security Directives
	// Hard limits prevent neighbor noise and resource exhaustion attacks.
	MemLimitBytes = 512 * 1024 * 1024 // 512MB
	CPUShares     = 1024
	PidsMax       = 64 // Limits fork bombs
	EnvSandboxID  = "SFW_SANDBOX_ID"
	RuntimeBinary = "runsc"
)

// IsSandboxed checks if the current process is already running inside the sandbox.
// This prevents infinite recursion if the worker accidentally calls Run().
func IsSandboxed() bool {
	return os.Getenv(EnvSandboxID) != ""
}

// Run executes the current binary (self) inside a gVisor sandbox.
// It streams stdout and stderr directly to the provided writers to prevent memory buffering
// which could be exploited to crash the parent via OOM.
func Run(ctx context.Context, cfg Config, stdout, stderr io.Writer) error {
	// Locates the OCI runtime binary; vital for delegation.
	runscPath, err := lookPathFunc(RuntimeBinary)
	if err != nil {
		return fmt.Errorf("security critical: '%s' not found in PATH: %w", RuntimeBinary, err)
	}

	// Prepares a unified bundle directory for OCI compliance.
	bundleDir, err := os.MkdirTemp("", "sfw-sandbox-*")
	if err != nil {
		return fmt.Errorf("failed to create bundle dir: %w", err)
	}
	defer os.RemoveAll(bundleDir)

	// Creates rootfs which acts as the overlay base.
	rootfs := filepath.Join(bundleDir, "rootfs")
	if err := os.Mkdir(rootfs, 0755); err != nil {
		return fmt.Errorf("failed to create rootfs: %w", err)
	}

	// Resolves the current executable to re-execute it inside the container.
	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate self executable: %w", err)
	}
	selfExe, err = filepath.EvalSymlinks(selfExe)
	if err != nil {
		return err
	}

	// Generates the strict OCI specification.
	spec, err := generateSpec(ctx, cfg, selfExe)
	if err != nil {
		return fmt.Errorf("failed to generate OCI spec: %w", err)
	}

	// Ensures all mount destinations exist in the rootfs.
	// OCI runtimes fail hard if the bind target is missing.
	if err := prepareMountPoints(rootfs, spec.Mounts); err != nil {
		return fmt.Errorf("failed to prepare mount points: %w", err)
	}

	configData, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal OCI spec: %w", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), configData, 0644); err != nil {
		return fmt.Errorf("failed to write config.json: %w", err)
	}

	// Determines isolation platform. KVM is preferred for performance;
	// ptrace is the fallback for environments without hardware viz.
	platform := "ptrace"
	if _, err := os.Stat("/dev/kvm"); err == nil {
		platform = "kvm"
	}

	// Executes runsc with rootless constraints and network isolation.
	// We use the mockable execCmdFunc here.
	cmd := execCmdFunc(ctx, runscPath,
		"--rootless",
		"--network=none",
		"--platform="+platform,
		"run",
		"-b", bundleDir,
		filepath.Base(bundleDir),
	)

	// Wires streams directly.
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Returns the error (including ExitError) so the caller can handle exit codes.
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// prepareMountPoints ensures that the destination paths for all mounts exist in the rootfs.
// It correctly handles File to File vs Directory to Directory binding.
func prepareMountPoints(rootfs string, mounts []Mount) error {
	for _, m := range mounts {
		dest := filepath.Join(rootfs, m.Destination)
		isDir := true

		// Matches the source type (file vs dir) to avoid "not a directory" errors.
		if m.Type == "bind" {
			fi, err := os.Stat(m.Source)
			if err != nil {
				// Fail early for clarity if source is missing.
				return fmt.Errorf("mount source missing: %s", m.Source)
			}
			isDir = fi.IsDir()
		}

		if isDir {
			if err := os.MkdirAll(dest, 0755); err != nil {
				return fmt.Errorf("failed to create mount dir %s: %w", dest, err)
			}
		} else {
			// Ensures parent dir exists.
			if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %w", dest, err)
			}
			// Creates empty file to mount over.
			if err := os.WriteFile(dest, []byte{}, 0644); err != nil {
				return fmt.Errorf("failed to create mount file %s: %w", dest, err)
			}
		}
	}
	return nil
}

// resolveSystemGoroot attempts to find the GOROOT of the host system.
// runtime.GOROOT() is unreliable as it returns the build time path (often empty if -trimpath is used).
func resolveSystemGoroot(ctx context.Context) string {
	// First, check the environment variable explicitly.
	if env := os.Getenv("GOROOT"); env != "" {
		return env
	}

	// Fallback: Ask the go tool. This is mockable via execCmdFunc.
	// We ignore errors here as the go tool might not be installed in the minimal run env.
	cmd := execCmdFunc(ctx, "go", "env", "GOROOT")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		return strings.TrimSpace(out.String())
	}
	return ""
}

func generateSpec(ctx context.Context, cfg Config, selfExe string) (*Spec, error) {
	// Identifies System Library Paths to support dynamic linking and go toolchain.
	libPaths := []string{"/lib", "/usr/lib", "/lib64", "/bin", "/usr/bin"}

	// Dynamically resolving GOROOT handles -trimpath builds correctly.
	if goroot := resolveSystemGoroot(ctx); goroot != "" {
		libPaths = append(libPaths, goroot)
	}

	// Builds Mounts.
	mounts := []Mount{
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "noexec", "nodev", "mode=1777"}},
		// Mounts Self to /app/sfw.
		{Destination: "/app/sfw", Type: "bind", Source: selfExe, Options: []string{"ro", "bind"}},
	}

	// Binds System Libraries (Read Only).
	for _, p := range libPaths {
		if _, err := os.Stat(p); err == nil {
			mounts = append(mounts, Mount{Destination: p, Type: "bind", Source: p, Options: []string{"ro", "rbind"}})
		}
	}

	// Binds User Inputs (Read Only).
	for _, m := range cfg.Mounts {
		// Ensures strict absolute paths for OCI compliance.
		abs, err := filepath.Abs(m)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve mount path %s: %w", m, err)
		}
		// Fails if user requested mount does not exist to prevent runtime ambiguity.
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("requested mount path missing: %s", m)
		}
		mounts = append(mounts, Mount{Destination: abs, Type: "bind", Source: abs, Options: []string{"ro", "rbind"}})
	}

	env := []string{
		"PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"GOCACHE=/tmp/gocache",
		"GOPATH=/tmp/gopath",
		"HOME=/tmp",
		fmt.Sprintf("%s=1", EnvSandboxID),
	}

	return &Spec{
		Version: "1.0.0",
		Root: &Root{
			Path:     "rootfs",
			Readonly: true, // Enforces read only overlay compliance.
		},
		Process: &Process{
			User: User{UID: 0, GID: 0}, // Root inside user namespace.
			Args: append([]string{"/app/sfw"}, cfg.Args...),
			Env:  env,
			Cwd:  cfg.WorkDir,
			// Explicitly empty slices ensure JSON marshaling outputs "[]" instead of null.
			// This signals "drop all" rather than "use default".
			Capabilities: &Capabilities{
				Bounding:  []string{},
				Effective: []string{},
			},
			Rlimits: []Rlimit{
				{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
			},
			NoNewPrivileges: true,
		},
		Mounts: mounts,
		Linux: &Linux{
			Namespaces: []Namespace{
				{Type: "pid"},
				{Type: "network"}, // Enforce Air Gap.
				{Type: "ipc"},
				{Type: "uts"},
				{Type: "mount"},
				{Type: "user"}, // Required for rootless.
			},
			UIDMappings: []IDMapping{
				{ContainerID: 0, HostID: os.Getuid(), Size: 1},
			},
			GIDMappings: []IDMapping{
				{ContainerID: 0, HostID: os.Getgid(), Size: 1},
			},
			Resources: &Resources{
				Memory: &Memory{Limit: MemLimitBytes},
				CPU:    &CPU{Shares: CPUShares},
				Pids:   &Pids{Limit: PidsMax},
			},
		},
	}, nil
}
