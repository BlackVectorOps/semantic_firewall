// Package actiontest runs the GitHub Action's shell steps (action.yml)
// against fixture repositories with a freshly built sfw.
package actiontest

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

// TestMain removes the sfw build of sfwOnPath when the tests are done; each
// run would otherwise leave its binary in the temp directory.
func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// sfwOnPath builds sfw once and returns a directory holding an `sfw`
// wrapper that runs it with --no-sandbox (the test host has no runsc).
func sfwOnPath(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		binDir, buildErr = os.MkdirTemp("", "sfw-action-bin-")
		if buildErr != nil {
			return
		}
		real := filepath.Join(binDir, "sfw-real")
		cmd := exec.Command(goBin(), "build", "-o", real, "github.com/BlackVectorOps/semantic_firewall/v7/cmd/sfw")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("building sfw: %v\n%s", err, out)
			return
		}
		wrapper := "#!/bin/bash\ncmd=$1; shift\ncase \"$cmd\" in\n" +
			"  deps) sub=$1; shift; exec " + real + " deps \"$sub\" --no-sandbox \"$@\" ;;\n" +
			"  *) exec " + real + " \"$cmd\" --no-sandbox \"$@\" ;;\nesac\n"
		buildErr = os.WriteFile(filepath.Join(binDir, "sfw"), []byte(wrapper), 0o755)
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binDir
}

func goBin() string { return filepath.Join(runtime.GOROOT(), "bin", "go") }

// stepScript returns the `run` block of the action.yml step with this id.
func stepScript(t *testing.T, id string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "id: "+id {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "run: |" {
				indent := len(lines[j]) - len(strings.TrimLeft(lines[j], " "))
				var block []string
				for _, b := range lines[j+1:] {
					if strings.TrimSpace(b) != "" && len(b)-len(strings.TrimLeft(b, " ")) <= indent {
						break
					}
					if len(b) > indent+2 {
						b = b[indent+2:]
					} else {
						b = strings.TrimLeft(b, " ")
					}
					block = append(block, b)
				}
				return strings.Join(block, "\n")
			}
			if strings.HasPrefix(strings.TrimSpace(lines[j]), "- name:") {
				break
			}
		}
	}
	t.Fatalf("action.yml has no step %q with a run block", id)
	return ""
}

// actionRun is the outcome of running the prep and run-sfw steps.
type actionRun struct {
	exitCode int
	log      string
	outputs  map[string]string
}

// runAction runs the prep and run-sfw steps in repo for one mode, the way
// the composite action wires them, and returns the exit code of run-sfw.
// The event is a push whose before commit is HEAD~1, unless inputs says
// otherwise.
func runAction(t *testing.T, repo string, inputs map[string]string) actionRun {
	t.Helper()
	res, prepOK := runSteps(t, repo, inputs)
	if !prepOK {
		t.Fatalf("prep step failed (%d):\n%s", res.exitCode, res.log)
	}
	return res
}

// runSteps is runAction, except that a failing prep step is returned (with
// prepOK false) rather than fatal.
func runSteps(t *testing.T, repo string, inputs map[string]string) (res actionRun, prepOK bool) {
	t.Helper()
	bin := sfwOnPath(t)
	outFile := filepath.Join(t.TempDir(), "github_output")
	if err := os.WriteFile(outFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GITHUB_") && !strings.HasPrefix(e, "INPUT_") && !strings.HasPrefix(e, "PATH=") && !strings.HasPrefix(e, "RUNNER_") {
			env = append(env, e)
		}
	}
	before := ""
	if out, err := exec.Command("git", "-C", repo, "rev-parse", "-q", "--verify", "HEAD~1^{commit}").Output(); err == nil {
		before = strings.TrimSpace(string(out))
	}
	env = append(env,
		"PATH="+bin+string(os.PathListSeparator)+filepath.Join(runtime.GOROOT(), "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_OUTPUT="+outFile, "GITHUB_EVENT_NAME=push", "GITHUB_EVENT_BEFORE="+before, "GITHUB_BASE_REF=",
		"RUNNER_TEMP="+t.TempDir(), "PR_HEAD_SHA=", "MG_BASE_SHA=", "MG_HEAD_SHA=", "DEFAULT_BRANCH=")
	for k, v := range inputs {
		env = append(env, k+"="+v)
	}

	run := func(script string, env []string) (int, string) {
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = repo
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("running step: %v", err)
		}
		return code, string(out)
	}

	// A shell error inside a step can leave the outputs looking right (a
	// failed [[ ]] test reads as false); none is acceptable.
	checkShell := func(log string) {
		for _, bad := range []string{"syntax error", "command not found", "unbound variable", "bad substitution"} {
			if strings.Contains(log, bad) {
				t.Fatalf("shell error (%q) while running the Action:\n%s", bad, log)
			}
		}
	}

	code, log := run(stepScript(t, "prep"), env)
	checkShell(log)
	if code != 0 {
		return actionRun{exitCode: code, log: log, outputs: parseOutputs(t, outFile)}, false
	}
	prep := parseOutputs(t, outFile)
	env = append(env,
		"PREP_BASE_SHA="+prep["base_sha"],
		"PREP_WORKTREE_DIR="+prep["worktree_dir"],
		"PREP_PAIRS_FILE="+prep["pairs_file"],
		"PREP_PAIR_COUNT="+prep["pair_count"],
		"PREP_HAS_MOD_CHANGES="+prep["has_mod_changes"])
	code, runLog := run(stepScript(t, "run-sfw"), env)
	all := log + runLog
	checkShell(all)
	return actionRun{exitCode: code, log: all, outputs: parseOutputs(t, outFile)}, true
}

// parseOutputs reads a GITHUB_OUTPUT file: name=value lines and
// name<<DELIM heredocs.
func parseOutputs(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Text()
		if name, delim, ok := strings.Cut(line, "<<"); ok && !strings.Contains(name, "=") {
			var body []string
			for sc.Scan() && sc.Text() != delim {
				body = append(body, sc.Text())
			}
			out[name] = strings.Join(body, "\n")
			continue
		}
		if name, value, ok := strings.Cut(line, "="); ok {
			out[name] = value
		}
	}
	return out
}

// gitRepo creates a repository with two commits: base, then base with
// changes applied (a nil content deletes the file).
func gitRepo(t *testing.T, base map[string]string, changes map[string]*string) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, src string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	for name, src := range base {
		write(name, src)
	}
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	for name, src := range changes {
		if src == nil {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		write(name, *src)
	}
	git("add", "-A")
	git("commit", "-q", "-m", "change")
	return dir
}

func str(s string) *string { return &s }

func requireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "git", "jq", "bc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the Action needs %s on PATH: %v", tool, err)
		}
	}
}

const gomod = "module example.com/m\n\ngo 1.22\n"

// diffEntry is the part of one sfw diff result the tests read.
type diffEntry struct {
	OldFile   string `json:"old_file"`
	NewFile   string `json:"new_file"`
	Error     string `json:"error"`
	Functions []struct {
		Function string `json:"function"`
		Status   string `json:"status"`
		Risk     int    `json:"risk_score"`
	} `json:"functions"`
	Summary struct {
		HighRisk int `json:"high_risk_changes"`
	} `json:"summary"`
}

func TestActionDiffMode(t *testing.T) {
	requireTools(t)
	repo := gitRepo(t, map[string]string{
		"go.mod":           gomod,
		"p/a.go":           "package p\n\nimport \"fmt\"\n\nfunc Handle(c string) { fmt.Println(c) }\n",
		"p/del.go":         "package p\n\nfunc Deleted() {}\n",
		"p/old_name.go":    "package p\n\nfunc Renamed(x int) int { return x + 1 }\n",
		"p/a_test.go":      "package p\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {}\n",
		"q/q.go":           "package q\n\nfunc Q() int { return 1 }\n",
		"README.md":        "readme\n",
		"vendor/v/v.go":    "package v\n",
		"p/z_generated.go": "package p\n\nfunc Gen() int { return 1 }\n",
	}, map[string]*string{
		"p/a.go":           str("package p\n\nimport \"os/exec\"\n\nfunc Handle(c string) { exec.Command(c).Run() }\n"),
		"p/new.go":         str("package p\n\nimport \"net\"\n\nfunc Added(a string) { net.Dial(\"tcp\", a) }\n"),
		"p/del.go":         nil,
		"p/old_name.go":    nil,
		"p/new_name.go":    str("package p\n\nfunc Renamed(x int) int { return x + 1 }\n"),
		"p/a_test.go":      str("package p\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { t.Log(1) }\n"),
		"q/q.go":           str("package q\n\nfunc Q() int { return 2 }\n"),
		"README.md":        str("changed\n"),
		"vendor/v/v.go":    str("package v\n\nfunc V() {}\n"),
		"p/z_generated.go": str("package p\n\nfunc Gen() int { return 2 }\n"),
	})
	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": "."})
	if res.exitCode != 0 {
		t.Fatalf("diff mode exit %d:\n%s", res.exitCode, res.log)
	}
	var entries []diffEntry
	if err := json.Unmarshal([]byte(res.outputs["result"]), &entries); err != nil {
		t.Fatalf("result is not a JSON array: %v\n%s", err, res.outputs["result"])
	}
	// Test and non-Go files are not diffed. A deleted file is diffed
	// against /dev/null, and listed here as "-" and its old path.
	got := map[string]diffEntry{}
	for _, e := range entries {
		name := e.NewFile
		if name == "/dev/null" {
			name = "-" + e.OldFile
		}
		got[name] = e
	}
	want := []string{"p/a.go", "p/new.go", "p/new_name.go", "q/q.go", "vendor/v/v.go", "p/z_generated.go", "-p/del.go"}
	if len(entries) != len(want) {
		t.Fatalf("diffed %d files; want %v:\n%s", len(entries), want, res.outputs["result"])
	}
	for _, f := range want {
		e, ok := got[f]
		if !ok || e.Error != "" {
			t.Errorf("%s: entry %+v; want a clean diff", f, e)
		}
	}
	if got["p/a.go"].Summary.HighRisk == 0 || got["p/new.go"].Summary.HighRisk == 0 {
		t.Errorf("a.go and new.go must carry high-risk changes: %+v %+v", got["p/a.go"], got["p/new.go"])
	}
	if e := got["p/new.go"]; e.OldFile != "/dev/null" {
		t.Errorf("added file's old side = %q; want /dev/null", e.OldFile)
	}
	if e := got["p/new_name.go"]; e.OldFile != "p/old_name.go" {
		t.Errorf("renamed file's old side = %q; want p/old_name.go", e.OldFile)
	}
	if pct := res.outputs["semantic-match-pct"]; pct == "" || pct == "100.0" {
		t.Errorf("semantic-match-pct = %q; want the average over the changed files", pct)
	}
}

func TestActionDiffModeFailsOnUnanalyzableFile(t *testing.T) {
	requireTools(t)
	repo := gitRepo(t, map[string]string{
		"go.mod": gomod,
		"p/a.go": "package p\n\nfunc A() int { return 1 }\n",
		"r/r.go": "package r\n\nfunc R() int { return 1 }\n",
	}, map[string]*string{
		"p/a.go": str("package p\n\nfunc A() int { return 2 }\n"),
		"r/r.go": str("package r\n\nfunc R() int { return undefinedThing }\n"),
	})
	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": "."})
	if res.exitCode == 0 {
		t.Fatalf("diff mode passed with an ill-typed file:\n%s", res.log)
	}
	if !strings.Contains(res.log, "sfw diff failed for 1 file(s)") || !strings.Contains(res.log, "::warning::sfw diff failed for r/r.go") {
		t.Errorf("log lacks the per-file failure:\n%s", res.log)
	}
	var entries []diffEntry
	if err := json.Unmarshal([]byte(res.outputs["result"]), &entries); err != nil || len(entries) != 2 {
		t.Fatalf("result = %v (%v); want both entries", res.outputs["result"], err)
	}
}

func TestActionDiffModeNoGoChanges(t *testing.T) {
	requireTools(t)
	repo := gitRepo(t, map[string]string{"go.mod": gomod, "p/a.go": "package p\n", "README.md": "a\n"},
		map[string]*string{"README.md": str("b\n")})
	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": "."})
	if res.exitCode != 0 || res.outputs["result"] != "[]" || res.outputs["semantic-match-pct"] != "100.0" {
		t.Errorf("exit %d, result %q, pct %q; want 0, [], 100.0\n%s", res.exitCode, res.outputs["result"], res.outputs["semantic-match-pct"], res.log)
	}
}

// depsRepo is an app module using example.com/lib through a local replace,
// with lib's codec package changing between the commits.
func depsRepo(t *testing.T, oldCodec, newCodec string, bumpGoMod bool) string {
	t.Helper()
	appMod := "module example.com/app\n\ngo 1.22\n\nrequire example.com/lib v1.0.0\n\nreplace example.com/lib => ../lib\n"
	changes := map[string]*string{"lib/codec/codec.go": str(newCodec)}
	if bumpGoMod {
		changes["app/go.mod"] = str(appMod + "\n// bumped\n")
	}
	return gitRepo(t, map[string]string{
		"app/go.mod":         appMod,
		"app/main.go":        "package main\n\nimport _ \"example.com/lib/codec\"\n\nfunc main() {}\n",
		"lib/go.mod":         "module example.com/lib\n\ngo 1.22\n",
		"lib/codec/codec.go": oldCodec,
	}, changes)
}

const codecV1 = "package codec\n\nimport \"strings\"\n\nfunc Decode(b []byte) string { return strings.TrimSpace(string(b)) }\n"

func TestActionDepsMode(t *testing.T) {
	requireTools(t)
	beacon := "package codec\n\nimport (\n\t\"net\"\n\t\"strings\"\n)\n\nfunc Decode(b []byte) string { beacon(); return strings.TrimSpace(string(b)) }\n\nfunc beacon() { net.Dial(\"tcp\", \"203.0.113.7:443\") }\n"
	benign := "package codec\n\nimport \"strings\"\n\nfunc Decode(b []byte) string { return strings.ToLower(strings.TrimSpace(string(b))) }\n"

	t.Run("high-risk update fails", func(t *testing.T) {
		res := runAction(t, depsRepo(t, codecV1, beacon, true), map[string]string{"INPUT_MODE": "deps", "INPUT_PATH": "app", "INPUT_FAIL_ON_ALERT": "true"})
		if res.exitCode == 0 || res.outputs["high-risk-changes"] == "0" || res.outputs["high-risk-changes"] == "" {
			t.Fatalf("exit %d, high-risk-changes %q; want a failure with high-risk changes\n%s", res.exitCode, res.outputs["high-risk-changes"], res.log)
		}
		var out struct {
			Modules []struct {
				Path  string `json:"path"`
				Reach []struct {
					Function string   `json:"function"`
					Added    []string `json:"added"`
				} `json:"reach"`
			} `json:"modules"`
		}
		if err := json.Unmarshal([]byte(res.outputs["result"]), &out); err != nil || len(out.Modules) != 1 ||
			len(out.Modules[0].Reach) == 0 || out.Modules[0].Reach[0].Function != "example.com/lib/codec.Decode" {
			t.Errorf("result = %s (%v); want Decode newly reaching network", res.outputs["result"], err)
		}
	})
	t.Run("high-risk update with fail-on-alert off passes", func(t *testing.T) {
		res := runAction(t, depsRepo(t, codecV1, beacon, true), map[string]string{"INPUT_MODE": "deps", "INPUT_PATH": "app", "INPUT_FAIL_ON_ALERT": "false"})
		if res.exitCode != 0 || res.outputs["high-risk-changes"] == "0" {
			t.Errorf("exit %d, high-risk-changes %q; want a pass that still reports the changes\n%s", res.exitCode, res.outputs["high-risk-changes"], res.log)
		}
	})
	t.Run("benign update passes", func(t *testing.T) {
		res := runAction(t, depsRepo(t, codecV1, benign, true), map[string]string{"INPUT_MODE": "deps", "INPUT_PATH": "app", "INPUT_FAIL_ON_ALERT": "true"})
		if res.exitCode != 0 || res.outputs["high-risk-changes"] != "0" {
			t.Errorf("exit %d, high-risk-changes %q; want 0, 0\n%s", res.exitCode, res.outputs["high-risk-changes"], res.log)
		}
	})
	t.Run("no go.mod or go.sum change skips", func(t *testing.T) {
		res := runAction(t, depsRepo(t, codecV1, beacon, false), map[string]string{"INPUT_MODE": "deps", "INPUT_PATH": "app", "INPUT_FAIL_ON_ALERT": "true"})
		if res.exitCode != 0 || res.outputs["result"] != "{}" || res.outputs["high-risk-changes"] != "0" {
			t.Errorf("exit %d, result %q, high-risk-changes %q; want 0, {}, 0\n%s", res.exitCode, res.outputs["result"], res.outputs["high-risk-changes"], res.log)
		}
	})
	t.Run("a go.work that redirects a dependency fails", func(t *testing.T) {
		repo := gitRepo(t, map[string]string{
			"go.work":            "go 1.22\n\nuse (\n\t./app\n\t./lib\n)\n",
			"app/go.mod":         "module example.com/app\n\ngo 1.22\n",
			"app/main.go":        "package main\n\nimport _ \"example.com/lib/codec\"\n\nfunc main() {}\n",
			"lib/go.mod":         "module example.com/lib\n\ngo 1.22\n",
			"lib/codec/codec.go": codecV1,
		}, map[string]*string{
			"go.work":               str("go 1.22\n\nuse (\n\t./app\n\t./shadow\n)\n"),
			"shadow/go.mod":         str("module example.com/lib\n\ngo 1.22\n"),
			"shadow/codec/codec.go": str(beacon),
		})
		res := runAction(t, repo, map[string]string{"INPUT_MODE": "deps", "INPUT_PATH": "app", "INPUT_FAIL_ON_ALERT": "true"})
		if res.exitCode == 0 || res.outputs["high-risk-changes"] == "0" || !strings.Contains(res.outputs["result"], `"new_version": "use ./shadow"`) && !strings.Contains(res.outputs["result"], `"new_version":"use ./shadow"`) {
			t.Errorf("exit %d, high-risk-changes %q, result %s; want a failure naming use ./shadow\n%s", res.exitCode, res.outputs["high-risk-changes"], res.outputs["result"], res.log)
		}
	})
	t.Run("a go.work the change adds fails", func(t *testing.T) {
		repo := gitRepo(t, map[string]string{
			"app/go.mod":  "module example.com/app\n\ngo 1.22\n",
			"app/main.go": "package main\n\nfunc main() {}\n",
		}, map[string]*string{
			"go.work":               str("go 1.22\n\nuse (\n\t./app\n\t./shadow\n)\n"),
			"app/main.go":           str("package main\n\nimport _ \"example.com/lib/codec\"\n\nfunc main() {}\n"),
			"shadow/go.mod":         str("module example.com/lib\n\ngo 1.22\n"),
			"shadow/codec/codec.go": str("package codec\n\nimport \"net\"\n\nfunc init() { net.Dial(\"tcp\", \"203.0.113.7:443\") }\n"),
		})
		res := runAction(t, repo, map[string]string{"INPUT_MODE": "deps", "INPUT_PATH": "app", "INPUT_FAIL_ON_ALERT": "true"})
		if res.exitCode == 0 || res.outputs["high-risk-changes"] == "0" || !strings.Contains(res.outputs["result"], "use ./shadow") {
			t.Errorf("exit %d, high-risk-changes %q, result %s; want a failure naming use ./shadow\n%s", res.exitCode, res.outputs["high-risk-changes"], res.outputs["result"], res.log)
		}
	})
	t.Run("a go.work the change adds over a base with dependencies", func(t *testing.T) {
		// The base worktree sits inside the head's checkout. Searching on
		// past its root, go mod download would take the head's go.work,
		// which does not use the base module, and fetch nothing for it.
		proxy, cache := fileProxy(t, "example.com/dep", "v1.0.0", map[string]string{
			"go.mod": "module example.com/dep\n\ngo 1.22\n",
			"dep.go": "package dep\n\nconst D = 1\n",
		})
		env := []string{"GOPROXY=" + proxy, "GOSUMDB=off", "GOFLAGS=-mod=mod", "GOWORK=off"}
		appMod := "module example.com/app\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n"
		sum := goSum(t, appMod, "package main\n\nimport _ \"example.com/dep\"\n\nfunc main() {}\n", env)
		repo := gitRepo(t, map[string]string{
			"app/go.mod":  appMod,
			"app/go.sum":  sum,
			"app/main.go": "package main\n\nimport _ \"example.com/dep\"\n\nfunc main() {}\n",
		}, map[string]*string{
			// The head drops dep, so only the base's download fetches it.
			"go.work":               str("go 1.22\n\nuse (\n\t./app\n\t./shadow\n)\n"),
			"app/go.mod":            str("module example.com/app\n\ngo 1.22\n"),
			"app/go.sum":            nil,
			"app/main.go":           str("package main\n\nimport _ \"example.com/lib/codec\"\n\nfunc main() {}\n"),
			"shadow/go.mod":         str("module example.com/lib\n\ngo 1.22\n"),
			"shadow/codec/codec.go": str("package codec\n\nimport \"net\"\n\nfunc init() { net.Dial(\"tcp\", \"203.0.113.7:443\") }\n"),
		})
		res := runAction(t, repo, map[string]string{"INPUT_MODE": "deps", "INPUT_PATH": "app", "INPUT_FAIL_ON_ALERT": "true",
			"GOPROXY": proxy, "GOSUMDB": "off", "GOMODCACHE": cache})
		if strings.Contains(res.log, "sfw deps diff failed") || !strings.Contains(res.outputs["result"], "use ./shadow") || res.exitCode == 0 {
			t.Errorf("exit %d, result %s; want the redirect reported and a failure\n%s", res.exitCode, res.outputs["result"], res.log)
		}
	})
	t.Run("path that is not a module root fails", func(t *testing.T) {
		res := runAction(t, depsRepo(t, codecV1, benign, true), map[string]string{"INPUT_MODE": "deps", "INPUT_PATH": "lib/codec", "INPUT_FAIL_ON_ALERT": "true"})
		if res.exitCode == 0 || !strings.Contains(res.log, "needs 'path' to be a module root") {
			t.Errorf("exit %d; want a module-root error\n%s", res.exitCode, res.log)
		}
	})
}

// fileProxy serves one module version from a file:// GOPROXY and returns
// the proxy's URL and an empty module cache for the run to fill.
func fileProxy(t *testing.T, mod, version string, files map[string]string) (proxy, cache string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(mod), "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, src := range files {
		w, err := zw.Create(mod + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(src))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		version + ".zip":  buf.String(),
		version + ".mod":  files["go.mod"],
		version + ".info": fmt.Sprintf(`{"Version":%q}`, version),
		"list":            version + "\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cache = t.TempDir()
	t.Cleanup(func() {
		// The module cache is read-only; make it removable.
		filepath.Walk(cache, func(p string, _ os.FileInfo, _ error) error { os.Chmod(p, 0o755); return nil })
	})
	return "file://" + filepath.ToSlash(root), cache
}

// goSum returns the go.sum of a module with the given go.mod and main.go,
// as go mod tidy writes it in env, with a module cache of its own.
func goSum(t *testing.T, goMod, mainGo string, env []string) string {
	t.Helper()
	dir, cache := t.TempDir(), t.TempDir()
	t.Cleanup(func() {
		filepath.Walk(cache, func(p string, _ os.FileInfo, _ error) error { os.Chmod(p, 0o755); return nil })
	})
	env = append(env, "GOMODCACHE="+cache)
	for name, src := range map[string]string{"go.mod": goMod, "main.go": mainGo} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "mod", "tidy")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	sum, err := os.ReadFile(filepath.Join(dir, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	return string(sum)
}
