// -- internal/sandbox/manager.go --
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
	"sort"
	"strings"
)

// -- Internal Hooks for Testing --
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
	MemLimitBytes = 512 * 1024 * 1024 // 512MB
	CPUShares     = 1024
	PidsMax       = 64
	EnvSandboxID  = "SFW_SANDBOX_ID"
	RuntimeBinary = "runsc"
)

// Checks if the current process is already running inside the sandbox.
func IsSandboxed() bool {
	return os.Getenv(EnvSandboxID) != ""
}

// Run executes the current binary (self) inside a gVisor sandbox.
func Run(ctx context.Context, cfg Config, stdout, stderr io.Writer) error {
	runscPath, err := lookPathFunc(RuntimeBinary)
	if err != nil {
		return fmt.Errorf("security critical: '%s' not found in PATH: %w", RuntimeBinary, err)
	}

	bundleDir, err := os.MkdirTemp("", "sfw-sandbox-*")
	if err != nil {
		return fmt.Errorf("failed to create bundle dir: %w", err)
	}
	defer os.RemoveAll(bundleDir)

	rootfs := filepath.Join(bundleDir, "rootfs")
	// Ensure rootfs is executable
	if err := os.Mkdir(rootfs, 0755); err != nil {
		return fmt.Errorf("failed to create rootfs: %w", err)
	}

	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate self executable: %w", err)
	}
	selfExe, err = filepath.EvalSymlinks(selfExe)
	if err != nil {
		return err
	}

	spec, err := generateSpec(ctx, cfg, selfExe)
	if err != nil {
		return fmt.Errorf("failed to generate OCI spec: %w", err)
	}

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

	platform := "ptrace"
	if _, err := os.Stat("/dev/kvm"); err == nil {
		platform = "kvm"
	} else {
		if stderr != nil {
			fmt.Fprintf(stderr, "::warning::[Security] /dev/kvm unavailable. Using ptrace.\n")
		}
	}

	// Added --ignore-cgroups to improve stability in nested CI environments
	cmd := execCmdFunc(ctx, runscPath,
		"--rootless",
		"--ignore-cgroups",
		"--network=none",
		"--platform="+platform,
		"run",
		"--bundle", bundleDir,
		filepath.Base(bundleDir),
	)

	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Removed os.Exit.
	// Returning the error allows the caller (e.g., Audit) to handle failures gracefully
	// rather than crashing the entire tool when one file fails.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run sandboxed process: %w", err)
	}
	return nil
}

// Ensures that the destination paths for all mounts exist in the rootfs.
// Added strict escape validation to prevent path traversal via mount points.
func prepareMountPoints(rootfs string, mounts []Mount) error {
	for _, m := range mounts {
		dest := filepath.Join(rootfs, m.Destination)

		// Path Traversal Check
		// Ensure resolved destination is strictly within rootfs.
		rel, err := filepath.Rel(rootfs, dest)
		if err != nil || strings.HasPrefix(rel, "..") || strings.HasPrefix(rel, "/") {
			return fmt.Errorf("security violation: mount point '%s' attempts to escape rootfs", m.Destination)
		}

		isDir := true
		if m.Type == "bind" {
			fi, err := os.Stat(m.Source)
			if err != nil {
				return fmt.Errorf("mount source missing: %s", m.Source)
			}
			isDir = fi.IsDir()
		}

		if isDir {
			if err := os.MkdirAll(dest, 0755); err != nil {
				return fmt.Errorf("failed to create mount dir %s: %w", dest, err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %w", dest, err)
			}
			// Create mount point with 0755 to allow execution of bound binaries.
			// Previous 0644 caused "permission denied" in strict OCI runtimes/AppArmor.
			if err := os.WriteFile(dest, []byte{}, 0755); err != nil {
				return fmt.Errorf("failed to create mount file %s: %w", dest, err)
			}
		}
	}
	return nil
}

// Detects GOROOT, GOCACHE, and GOMODCACHE from the host.
func resolveGoToolchain(ctx context.Context) (goroot, gocache string) {
	getEnv := func(key string) string {
		if val := os.Getenv(key); val != "" {
			return val
		}
		cmd := execCmdFunc(ctx, "go", "env", key)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			return strings.TrimSpace(out.String())
		}
		return ""
	}
	return getEnv("GOROOT"), getEnv("GOCACHE")
}

func generateSpec(ctx context.Context, cfg Config, selfExe string) (*Spec, error) {
	libPaths := []string{"/lib", "/usr/lib", "/lib64", "/bin", "/usr/bin", "/usr/include", "/usr/local/include"}

	// Detect Toolchain Paths
	goroot, gocache := resolveGoToolchain(ctx)

	// Dynamically build PATH to include discovered GOROOT
	sandboxPath := "/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if goroot != "" {
		libPaths = append(libPaths, goroot)
		sandboxPath = fmt.Sprintf("%s/bin:%s", goroot, sandboxPath)
	}

	mounts := []Mount{
		// Removed "noexec" from /proc options.
		// "noexec" prevents the process from re-executing itself via /proc/self/exe,
		// which is required for Go binaries and the gVisor rootless shim.
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "nodev"}},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		// Removed "noexec" from /tmp to allow execution of build artifacts/scripts
		{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "mode=1777"}},
		{Destination: "/app/sfw", Type: "bind", Source: selfExe, Options: []string{"ro", "bind"}},
	}

	// Mount System Libraries
	for _, p := range libPaths {
		if _, err := os.Stat(p); err == nil {
			mounts = append(mounts, Mount{Destination: p, Type: "bind", Source: p, Options: []string{"ro", "rbind"}})
		}
	}

	// Mount GOCACHE (Read-Only) to allow reuse of build artifacts
	envCaches := []string{}
	if gocache != "" {
		if _, err := os.Stat(gocache); err == nil {
			// Mount to /gocache to avoid /tmp overlay issues
			mounts = append(mounts, Mount{Destination: "/gocache", Type: "bind", Source: gocache, Options: []string{"ro", "rbind"}})
			envCaches = append(envCaches, "GOCACHE=/gocache")
		}
	} else {
		envCaches = append(envCaches, "GOCACHE=/tmp/gocache")
	}

	// Define Reserved Paths to prevent shadowing critical sandbox infrastructure via user input.
	reservedPaths := map[string]bool{
		"/app/sfw": true,
		"/proc":    true,
		"/sys":     true,
		"/dev":     true,
		"/tmp":     true,
		"/gocache": true,
	}

	// Bind User Inputs
	for _, m := range cfg.Mounts {
		abs, err := filepath.Abs(m)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve mount path %s: %w", m, err)
		}

		// Check for Reserved Path Collision
		if reservedPaths[abs] {
			return nil, fmt.Errorf("security violation: mount path '%s' collides with reserved sandbox path", abs)
		}

		// Resolve Symlinks for the SOURCE (Data)
		finalPath, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve symlinks for %s: %w", abs, err)
		}

		if _, err := os.Stat(finalPath); err != nil {
			return nil, fmt.Errorf("requested mount path missing: %s", finalPath)
		}

		// Map the physical data (finalPath) to the logical path (abs)
		// This ensures the tool logic (which uses 'abs') finds the files where it expects them.
		mounts = append(mounts, Mount{
			Destination: abs, // The path the tool expects
			Type:        "bind",
			Source:      finalPath, // The actual data on disk
			Options:     []string{"ro", "rbind"},
		})
	}

	// Sort mounts to prevent shadowing.
	// Parents must be mounted before children (e.g., /app before /app/bin).
	// Lexicographical sort of Destination satisfies this for standard paths.
	sort.SliceStable(mounts, func(i, j int) bool {
		return mounts[i].Destination < mounts[j].Destination
	})

	env := []string{
		fmt.Sprintf("PATH=%s", sandboxPath),
		"GOPATH=/tmp/gopath",
		"HOME=/tmp",
		"GOPROXY=off", // Enforce Air Gap
		fmt.Sprintf("%s=1", EnvSandboxID),
	}
	env = append(env, envCaches...)

	return &Spec{
		Version: "1.0.0",
		Root: &Root{
			Path:     "rootfs",
			Readonly: true,
		},
		Process: &Process{
			User: User{UID: 0, GID: 0},
			Args: append([]string{"/app/sfw"}, cfg.Args...),
			Env:  env,
			Cwd:  cfg.WorkDir,
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
				{Type: "network"},
				{Type: "ipc"},
				{Type: "uts"},
				{Type: "mount"},
				{Type: "user"},
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
