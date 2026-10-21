package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The go command finds a file's module by walking up to the nearest go.mod;
// a .git entry on the way (a git submodule checked out inside the module,
// without a go.mod of its own) does not stop it, though it stops
// findContextRoot. Without the module root mounted, the file would load as
// an ad-hoc package inside the sandbox.
//
// the directory holding the go.mod that governs each
// input is mounted (README, Sandbox: "each input's go.mod/.git root").
func TestBatchMounts_SubmoduleWithoutGoMod(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"m/go.mod":     "module example.com/m\n\ngo 1.22\n",
		"m/util/u.go":  "package util\n\nfunc U() int { return 1 }\n",
		"m/sub/.git":   "gitdir: ../.git/modules/sub\n",
		"m/sub/x/x.go": "package x\n\nimport \"example.com/m/util\"\n\nfunc X() int { return util.U() }\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	input := filepath.Join(root, "m", "sub", "x", "x.go")
	pairsFile := writePairs(t, "\x00"+input+"\x00")

	// Unsandboxed, the file loads as part of module example.com/m.
	if err := RunDiffBatchLogic(RealFileSystem{}, &bytes.Buffer{}, pairsFile, false); err != nil {
		t.Fatalf("unsandboxed: %v", err)
	}

	pairs, err := ReadDiffPairs(RealFileSystem{}, pairsFile)
	if err != nil {
		t.Fatal(err)
	}
	sb := &recordingSandbox{}
	if err := SandboxExec(sb, io.Discard, io.Discard, "diff-batch", []string{pairsFile}, batchMounts(pairsFile, pairs)...); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(root, "m", "go.mod")
	visible := false
	for _, m := range sb.cfg.Mounts {
		if strings.HasPrefix(gomod, m+string(filepath.Separator)) {
			visible = true
		}
	}
	if !visible {
		t.Errorf("%s is not visible in the sandbox: mounts %v", gomod, sb.cfg.Mounts)
	}
}
