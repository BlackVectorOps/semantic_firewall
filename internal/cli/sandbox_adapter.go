// -- internal/cli/sandbox_adapter.go --
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/BlackVectorOps/semantic_firewall/v3/internal/sandbox"
)

// RealSandboxer implements the Sandboxer interface using the internal sandbox package.
type RealSandboxer struct{}

func (rs RealSandboxer) IsSandboxed() bool {
	return sandbox.IsSandboxed()
}

func (rs RealSandboxer) Run(ctx context.Context, cfg sandbox.Config, stdout, stderr io.Writer) error {
	return sandbox.Run(ctx, cfg, stdout, stderr)
}

// SandboxExec delegates the current command to the sandbox with explicit mount points.
func SandboxExec(sb Sandboxer, stdout, stderr io.Writer, command string, args []string, inputs ...string) error {
	// 0. Recursion Guard
	if sb.IsSandboxed() {
		return fmt.Errorf("process is already sandboxed; nested sandboxing is not supported")
	}

	// 1. Path Resolution & Context Setup
	var mounts []string

	// Mount the Current Working Directory (CWD) to preserve context for relative paths
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to determine CWD: %w", err)
	}
	mounts = append(mounts, cwd)

	// Mount explicit inputs
	for _, p := range inputs {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err == nil {
			mounts = append(mounts, abs)
		}
	}

	// 2. Prepare Configuration
	cfg := sandbox.Config{
		Args:    append([]string{command}, args...),
		Mounts:  mounts,
		WorkDir: cwd,
	}

	// 3. Execution & Signal Handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Invoke the sandbox manager with strict isolation
	if err := sb.Run(ctx, cfg, stdout, stderr); err != nil {
		// 4. Exit Code Propagation
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		}
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("operation cancelled")
		}
		return fmt.Errorf("sandboxed process failed: %w", err)
	}

	return nil
}
