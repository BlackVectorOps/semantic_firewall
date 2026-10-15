package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/internal/sandbox"
)

// recordingSandbox records the configuration it is asked to run.
type recordingSandbox struct{ cfg sandbox.Config }

func (r *recordingSandbox) IsSandboxed() bool { return false }

func (r *recordingSandbox) Run(_ context.Context, cfg sandbox.Config, _, _ io.Writer) error {
	r.cfg = cfg
	return nil
}

// A file of a module that a go.work above it governs is analyzed with the
// workspace's directory mounted, which holds the modules it uses; without
// a go.work only the module is.
func TestSandboxExec_MountsTheWorkspace(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"work/.git/HEAD":   "ref: refs/heads/main\n",
		"work/go.work":     "go 1.22\n\nuse (\n\t./app\n\t./lib\n)\n",
		"work/app/go.mod":  "module example.com/app\n",
		"work/app/a.go":    "package app\n",
		"work/lib/go.mod":  "module example.com/lib\n",
		"plain/.git/HEAD":  "ref: refs/heads/main\n",
		"plain/app/go.mod": "module example.com/app\n",
		"plain/app/a.go":   "package app\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for tree, mounted := range map[string]bool{"work": true, "plain": false} {
		sb := &recordingSandbox{}
		file := filepath.Join(root, tree, "app", "a.go")
		if err := SandboxExec(sb, io.Discard, io.Discard, "diff", nil, file); err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(sb.cfg.Mounts, filepath.Join(root, tree)); got != mounted {
			t.Errorf("%s: %s mounted = %v, want %v (mounts %v)", tree, filepath.Join(root, tree), got, mounted, sb.cfg.Mounts)
		}
		if !slices.Contains(sb.cfg.Mounts, filepath.Join(root, tree, "app")) {
			t.Errorf("%s: the module is not mounted: %v", tree, sb.cfg.Mounts)
		}
	}
}
