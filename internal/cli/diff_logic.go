// -- internal/cli/diff_logic.go --
package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/api"
)

// -- Public API --

func RunDiff(oldFile, newFile string, noSandbox bool) error {
	cleanOld := filepath.Clean(oldFile)
	cleanNew := filepath.Clean(newFile)
	sb := RealSandboxer{}
	fsys := RealFileSystem{}

	if !noSandbox && !sb.IsSandboxed() {
		args := []string{cleanOld, cleanNew}
		return SandboxExec(sb, os.Stdout, os.Stderr, "diff", args, cleanOld, cleanNew)
	}

	return RunDiffLogic(fsys, os.Stdout, cleanOld, cleanNew)
}

// -- Core Logic --

// RunDiffLogic is the CLI shim around api.DiffWithFS. The diff
// computation itself lives in pkg/api so external integrations (the
// MCP server, third-party Go callers) can invoke it without importing
// internal/cli.
func RunDiffLogic(fsys FileSystem, w io.Writer, oldFile, newFile string) error {
	diffOutput, err := api.DiffWithFS(fsys, oldFile, newFile)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(diffOutput)
}
