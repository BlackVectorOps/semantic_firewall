package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/api"
)

// RunDepsDiff compares the third-party code compiled into two trees of a
// module, inside the sandbox unless noSandbox is set.
func RunDepsDiff(oldDir, newDir string, noSandbox bool) error {
	// Checked before cleaning: Clean("") is ".", and a caller whose variable
	// came out empty would get the working directory diffed against itself,
	// reported as no change.
	if err := depsDiffDirs(oldDir, newDir); err != nil {
		return err
	}
	cleanOld, cleanNew := filepath.Clean(oldDir), filepath.Clean(newDir)
	sb := RealSandboxer{}
	if !noSandbox && !sb.IsSandboxed() {
		return SandboxExec(sb, os.Stdout, os.Stderr, "deps-diff", []string{cleanOld, cleanNew}, cleanOld, cleanNew)
	}
	return RunDepsDiffLogic(os.Stdout, cleanOld, cleanNew)
}

// RunDepsDiffLogic is the CLI shim around api.DepsDiff.
func RunDepsDiffLogic(w io.Writer, oldDir, newDir string) error {
	if err := depsDiffDirs(oldDir, newDir); err != nil {
		return err
	}
	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// depsDiffDirs rejects an empty directory argument. Unlike a diff's file,
// where an empty path stands for an absent side, a deps diff has no absent
// side: both trees must be named.
func depsDiffDirs(oldDir, newDir string) error {
	if oldDir == "" || newDir == "" {
		return fmt.Errorf("deps diff needs two module directories; got old %q and new %q", oldDir, newDir)
	}
	return nil
}
