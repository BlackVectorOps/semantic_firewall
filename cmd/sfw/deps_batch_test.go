package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeModule writes a module example.com/<name> with one package and
// returns its directory.
func writeModule(t *testing.T, name, src string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	for file, content := range map[string]string{
		"go.mod":  "module example.com/" + name + "\n\ngo 1.22\n",
		"main.go": src,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestWorkerDepsAndBatchArgs(t *testing.T) {
	for _, c := range []struct {
		args   []string
		errSub string
	}{
		{[]string{"deps-diff"}, "deps-diff worker requires two directories; got 0 arguments"},
		{[]string{"deps-diff", "a"}, "deps-diff worker requires two directories; got 1 arguments"},
		{[]string{"deps-diff", "a", "b", "c"}, "deps-diff worker requires two directories; got 3 arguments"},
		{[]string{"diff-batch"}, "diff-batch worker requires a pairs file; got 0 arguments"},
		{[]string{"diff-batch", "a", "b"}, "diff-batch worker requires a pairs file; got 2 arguments"},
	} {
		err := runWorker(c.args)
		if err == nil || err.Error() != c.errSub {
			t.Errorf("runWorker(%q) = %v; want %q", c.args, err, c.errSub)
		}
	}
}

func TestWorkerDepsAndBatchRun(t *testing.T) {
	src := "package main\n\nfunc main() {}\n"
	dir := writeModule(t, "app", src)

	// The workers write their JSON to stdout.
	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		var buf []byte
		tmp := make([]byte, 4096)
		for {
			n, err := r.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				done <- buf
				return
			}
		}
	}()
	pairs := filepath.Join(t.TempDir(), "pairs")
	file := filepath.Join(dir, "main.go")
	if err := os.WriteFile(pairs, []byte(file+"\x00"+file+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	depsErr := runWorker([]string{"deps-diff", dir, dir})
	batchErr := runWorker([]string{"diff-batch", pairs})
	w.Close()
	os.Stdout = stdout
	out := <-done

	if depsErr != nil || batchErr != nil {
		t.Fatalf("deps-diff: %v; diff-batch: %v", depsErr, batchErr)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var deps struct {
		OldDir  string `json:"old_dir"`
		Modules []any  `json:"modules"`
	}
	var batch []struct {
		NewFile string `json:"new_file"`
		Error   string `json:"error"`
	}
	if err := dec.Decode(&deps); err != nil {
		t.Fatalf("deps-diff output: %v\n%s", err, out)
	}
	if err := dec.Decode(&batch); err != nil {
		t.Fatalf("diff-batch output: %v\n%s", err, out)
	}
	if deps.OldDir != dir || deps.Modules == nil || len(deps.Modules) != 0 {
		t.Errorf("deps-diff output %+v; want old_dir %s and no modules", deps, dir)
	}
	if len(batch) != 1 || batch[0].NewFile != file || batch[0].Error != "" {
		t.Errorf("diff-batch output %+v; want one result for %s", batch, file)
	}
}

// The command line of deps diff and diff --batch, through the binary.
func TestMainBinaryDepsAndBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	bin := filepath.Join(t.TempDir(), "sfw")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := writeModule(t, "app", "package main\n\nfunc main() {}\n")
	file := filepath.Join(dir, "main.go")
	pairs := filepath.Join(t.TempDir(), "pairs")
	if err := os.WriteFile(pairs, []byte(file+"\x00"+file+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name     string
		args     []string
		exit     int
		contains string
	}{
		{"usage lists deps diff", nil, 1, "sfw deps diff <old-dir> <new-dir>"},
		{"usage lists diff --batch", nil, 1, "sfw diff --batch <pairs-file>"},
		{"deps without diff", []string{"deps"}, 1, "Usage: sfw deps diff [--no-sandbox] <old-module-dir> <new-module-dir>"},
		{"deps with another subcommand", []string{"deps", "list"}, 1, "Usage: sfw deps diff"},
		{"deps diff with one directory", []string{"deps", "diff", "--no-sandbox", dir}, 1, "Usage: sfw deps diff"},
		{"deps diff", []string{"deps", "diff", "--no-sandbox", dir, dir}, 0, `"modules": []`},
		{"deps diff of a non-module", []string{"deps", "diff", "--no-sandbox", t.TempDir(), dir}, 1, "old tree: "},
		{"diff --batch with positional arguments", []string{"diff", "--batch", pairs, file}, 1, "no positional arguments"},
		{"diff --batch", []string{"diff", "--no-sandbox", "--batch", pairs}, 0, `"new_file": "` + file + `"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(bin, c.args...)
			out, _ := cmd.CombinedOutput()
			if code := cmd.ProcessState.ExitCode(); code != c.exit || !strings.Contains(string(out), c.contains) {
				t.Errorf("exit %d, output:\n%s\nwant exit %d and %q", code, out, c.exit, c.contains)
			}
		})
	}
}
