// -- internal/cli/sandbox_adapter.go --
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	// Use "internal-worker" prefix to route to the worker dispatch logic
	// which handles flag parsing differently than the standard CLI.
	cfg := sandbox.Config{
		Args:    append([]string{"internal-worker", command}, args...),
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

// PrepareSandboxDB ensures a database is usable inside the sandbox.
// If running sandboxed (where mounts are typically ReadOnly), PebbleDB fails to lock.
// This copies the DB to a secure, writable temp directory.
// Returns: newPath, cleanupFunc, error
func PrepareSandboxDB(originalPath string) (string, func(), error) {
	if !sandbox.IsSandboxed() {
		return originalPath, func() {}, nil
	}

	// Security: Use MkdirTemp to avoid collisions or symlink attacks in shared environments
	tmpDir, err := os.MkdirTemp("", "sfw_sigdb_")
	if err != nil {
		return "", func() {}, fmt.Errorf("failed to create temp dir: %w", err)
	}

	cleanup := func() { os.RemoveAll(tmpDir) }

	// Copy content using shared robust logic
	if err := copyDir(originalPath, tmpDir); err != nil {
		cleanup() // Clean up partial copy
		return "", func() {}, fmt.Errorf("failed to copy database: %w", err)
	}

	return tmpDir, cleanup, nil
}

// copyDir recursively copies a directory tree from src to dst.
func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source is not a directory: %s", src)
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("create dest dir: %w", err)
	}

	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Security: Skip symlinks during DB copy to avoid escaping destination
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		return copyFile(path, dstPath)
	})
}

// copyFile copies a single file from src to dst using a buffer.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Use CopyBuffer with a 32KB buffer to minimize syscalls
	buf := make([]byte, 32*1024)
	if _, err := io.CopyBuffer(dstFile, srcFile, buf); err != nil {
		return err
	}

	return nil
}
