package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/api"
)

// RunDepsDiff compares the third-party code compiled into two trees of a
// module, inside the sandbox unless noSandbox is set.
func RunDepsDiff(oldDir, newDir string, noSandbox bool) error {
	cleanOld, cleanNew := filepath.Clean(oldDir), filepath.Clean(newDir)
	sb := RealSandboxer{}
	if !noSandbox && !sb.IsSandboxed() {
		return SandboxExec(sb, os.Stdout, os.Stderr, "deps-diff", []string{cleanOld, cleanNew}, cleanOld, cleanNew)
	}
	return RunDepsDiffLogic(os.Stdout, cleanOld, cleanNew)
}

// RunDepsDiffLogic is the CLI shim around api.DepsDiff.
func RunDepsDiffLogic(w io.Writer, oldDir, newDir string) error {
	out, err := api.DepsDiff(oldDir, newDir)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
