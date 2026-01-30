// -- internal/cli/sandbox_adapter.go --
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/BlackVectorOps/semantic_firewall/v3/internal/sandbox"
)

// Implements the Sandboxer interface using the internal sandbox package.
type RealSandboxer struct{}

func (rs RealSandboxer) IsSandboxed() bool {
	return sandbox.IsSandboxed()
}

func (rs RealSandboxer) Run(ctx context.Context, cfg sandbox.Config, stdout, stderr io.Writer) error {
	return sandbox.Run(ctx, cfg, stdout, stderr)
}

// Walks up the directory tree to find the context root for a file.
// It looks for go.mod, .git, or specific worktree patterns.
func findContextRoot(path string) string {
	dir := path
	if fi, err := os.Stat(dir); err == nil && !fi.IsDir() {
		dir = filepath.Dir(dir)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}

	current := abs
	for {
		// Check for Module definition (Critical for Go Tools)
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		// Check for Git root/worktree (Critical for Git Tools)
		if _, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			return current
		}
		// Check for SFW specific temporary worktrees
		base := filepath.Base(current)
		if strings.HasPrefix(base, ".sfw_worktree_") || strings.HasPrefix(base, ".sfw_temp_") {
			return current
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return ""
}

// elegates the current command to the sandbox with explicit mount points.
func SandboxExec(sb Sandboxer, stdout, stderr io.Writer, command string, args []string, inputs ...string) error {
	if sb.IsSandboxed() {
		return fmt.Errorf("process is already sandboxed; nested sandboxing is not supported")
	}

	// 1. Path Resolution & Context Setup
	// Use a map to deduplicate mounts
	mountMap := make(map[string]bool)
	var mounts []string

	addMount := func(p string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err == nil {
			if !mountMap[abs] {
				mountMap[abs] = true
				mounts = append(mounts, abs)
			}
		}
	}

	// Mount the Current Working Directory (CWD)
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to determine CWD: %w", err)
	}
	addMount(cwd)

	// Mount explicit inputs and their detected roots
	for _, p := range inputs {
		if p == "" {
			continue
		}
		addMount(p)

		//  Auto detect and bind mount Worktree/Module Root
		// This ensures that even if we analyze a single file deep in a worktree,
		// the toolchain sees the 'go.mod' and '.git' at the root.
		if root := findContextRoot(p); root != "" {
			addMount(root)
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

	if err := sb.Run(ctx, cfg, stdout, stderr); err != nil {
		// Bubble up the error to the caller
		// so it can decide whether to fail closed, report a warning, or continue.
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("operation cancelled")
		}
		return fmt.Errorf("sandboxed process failed: %w", err)
	}

	return nil
}
