// -- internal/cli/diff_logic.go --
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/api"
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

// RunDiffBatch diffs the file pairs listed in pairsFile (see
// ReadDiffPairs), inside the sandbox unless noSandbox is set.
func RunDiffBatch(pairsFile string, noSandbox bool) error {
	cleanPairs := filepath.Clean(pairsFile)
	sb := RealSandboxer{}
	fsys := RealFileSystem{}
	if !noSandbox && !sb.IsSandboxed() {
		pairs, err := ReadDiffPairs(fsys, cleanPairs)
		if err != nil {
			return err
		}
		// Mount the pairs file and the context root of every input (or its
		// directory when it has none) rather than each file.
		inputs := []string{cleanPairs}
		seen := map[string]bool{}
		for _, p := range pairs {
			for _, f := range []string{p.Old, p.New} {
				if f == "" || f == os.DevNull {
					continue
				}
				m := findContextRoot(f)
				if m == "" {
					m = filepath.Dir(f)
				}
				if !seen[m] {
					seen[m] = true
					inputs = append(inputs, m)
				}
			}
		}
		return SandboxExec(sb, os.Stdout, os.Stderr, "diff-batch", []string{cleanPairs}, inputs...)
	}
	return RunDiffBatchLogic(fsys, os.Stdout, cleanPairs)
}

// RunDiffBatchLogic prints the JSON array of api.DiffBatch results for the
// pairs in pairsFile, in order. It returns an error, after printing, when a
// pair could not be diffed; that pair's entry carries the reason in "error".
func RunDiffBatchLogic(fsys FileSystem, w io.Writer, pairsFile string) error {
	pairs, err := ReadDiffPairs(fsys, pairsFile)
	if err != nil {
		return err
	}
	results := api.DiffBatchWithFS(fsys, pairs)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return err
	}
	failed := 0
	for _, r := range results {
		if r.ErrorMessage != "" {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d file pair(s) could not be diffed", failed, len(results))
	}
	return nil
}

// ReadDiffPairs reads a pairs file: NUL-terminated paths, alternately the
// old and the new version of each file ("old1\x00new1\x00old2\x00new2\x00").
// An empty path stands for an absent side.
func ReadDiffPairs(fsys FileSystem, pairsFile string) ([]api.DiffPair, error) {
	data, err := fsys.ReadFile(pairsFile)
	if err != nil {
		return nil, fmt.Errorf("reading pairs file: %w", err)
	}
	if len(data) == 0 {
		return []api.DiffPair{}, nil
	}
	if data[len(data)-1] != 0 {
		return nil, fmt.Errorf("pairs file %s: last path is not NUL-terminated", pairsFile)
	}
	fields := strings.Split(string(data[:len(data)-1]), "\x00")
	if len(fields)%2 != 0 {
		return nil, fmt.Errorf("pairs file %s: %d paths; want old/new pairs", pairsFile, len(fields))
	}
	pairs := make([]api.DiffPair, 0, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		pairs = append(pairs, api.DiffPair{Old: fields[i], New: fields[i+1]})
	}
	return pairs, nil
}
