// -- internal/cli/diff_logic.go --
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/api"
)

// -- Public API --

func RunDiff(oldFile, newFile string, noSandbox bool) error {
	cleanOld := cleanDiffPath(oldFile)
	cleanNew := cleanDiffPath(newFile)
	sb := RealSandboxer{}
	fsys := RealFileSystem{}

	if !noSandbox && !sb.IsSandboxed() {
		args := []string{cleanOld, cleanNew}
		var mounts []string
		for _, f := range args {
			// A missing input stands for an absent side and has nothing to
			// mount.
			if _, err := os.Stat(f); err == nil {
				mounts = append(mounts, f)
			}
		}
		return SandboxExec(sb, os.Stdout, os.Stderr, "diff", args, mounts...)
	}

	return RunDiffLogic(fsys, os.Stdout, cleanOld, cleanNew)
}

// cleanDiffPath cleans a diff input's path. An empty path stays empty: it
// stands for the absent side of an added or removed file, where a cleaned
// one would name the current directory.
func cleanDiffPath(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
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
		return SandboxExec(sb, os.Stdout, os.Stderr, "diff-batch", []string{cleanPairs}, batchMounts(cleanPairs, pairs)...)
	}
	return RunDiffBatchLogic(fsys, os.Stdout, cleanPairs)
}

// batchMounts lists what a sandboxed batch needs to see: the pairs file,
// the context root (see findContextRoot) of every input, each once rather
// than each file, and the input itself when it has no root or resolves
// outside it (a symbolic link to a file elsewhere; the sandbox mounts a
// link's target at the link's path). A missing input stands for an absent
// side and has nothing to mount.
func batchMounts(pairsFile string, pairs []api.DiffPair) []string {
	inputs := []string{pairsFile}
	seen := map[string]bool{}
	add := func(m string) {
		if !seen[m] {
			seen[m] = true
			inputs = append(inputs, m)
		}
	}
	for _, p := range pairs {
		for _, f := range []string{p.Old, p.New} {
			if f == "" || f == os.DevNull {
				continue
			}
			target, err := filepath.EvalSymlinks(f)
			if err != nil {
				continue
			}
			root := findContextRoot(f)
			if root == "" {
				add(f)
				continue
			}
			add(root)
			if !inDir(target, root) {
				add(f)
			}
		}
	}
	return inputs
}

// inDir reports whether path, with its links resolved, is inside dir with
// its links resolved.
func inDir(path, dir string) bool {
	path, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
