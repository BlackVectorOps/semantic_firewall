package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// A sandboxed batch must be able to read every input it diffs. For an input
// that is a symbolic link out of its module (a file shared across a
// monorepo's modules), the link's target is in no mounted root: inside the
// sandbox the link would dangle and the diff would take the file as absent,
// its functions vanishing without an error. The batch mounts such an input
// itself, as a single `sfw diff` does; the sandbox mounts the target at the
// link's path.
func TestBatchMounts_SymlinkOutOfItsRoot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"repo/.git/HEAD":     "ref: refs/heads/main\n",
		"repo/lib/shared.go": "package p\n\nimport \"os/exec\"\n\nfunc Handle(s string) { exec.Command(s).Run() }\n",
		"repo/svc/go.mod":    "module example.com/svc\n\ngo 1.22\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	input := filepath.Join(root, "repo", "svc", "p", "shared.go")
	if err := os.MkdirAll(filepath.Dir(input), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "lib", "shared.go"), input); err != nil {
		t.Fatal(err)
	}
	pairsFile := writePairs(t, "\x00"+input+"\x00")
	pairs, err := ReadDiffPairs(RealFileSystem{}, pairsFile)
	if err != nil {
		t.Fatal(err)
	}

	// Outside the sandbox the pair is a high-risk added function.
	var buf bytes.Buffer
	if err := RunDiffBatchLogic(RealFileSystem{}, &buf, pairsFile); err != nil {
		t.Fatalf("RunDiffBatchLogic: %v", err)
	}
	var out []models.DiffOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out[0].Summary.HighRiskChanges == 0 {
		t.Fatalf("unsandboxed: %+v; want Handle added as a high-risk change", out[0].Summary)
	}

	// What RunDiffBatch hands the sandbox.
	sb := &recordingSandbox{}
	if err := SandboxExec(sb, io.Discard, io.Discard, "diff-batch", []string{pairsFile}, batchMounts(pairsFile, pairs)...); err != nil {
		t.Fatal(err)
	}
	mounted := false
	for _, m := range sb.cfg.Mounts {
		mounted = mounted || m == input
	}
	if !mounted {
		t.Errorf("mounts %v; want the input %s itself, its target being outside its root", sb.cfg.Mounts, input)
	}
}

func TestInDir(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		path string
		in   bool
	}{
		{dir, true},
		{filepath.Join(dir, "a.go"), true},
		{filepath.Join(dir, "..a.go"), true},
		{filepath.Join(dir, "p", "a.go"), true},
		{filepath.Dir(dir), false},
		{dir + "x", false},
		{filepath.Join(filepath.Dir(dir), "y", "a.go"), false},
	} {
		if got := inDir(c.path, dir); got != c.in {
			t.Errorf("inDir(%q, %q) = %v; want %v", c.path, dir, got, c.in)
		}
	}
	// A directory named through a link is the directory it links to.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if !inDir(filepath.Join(dir, "a.go"), link) {
		t.Errorf("inDir(%q, %q) = false; want true", filepath.Join(dir, "a.go"), link)
	}
}
