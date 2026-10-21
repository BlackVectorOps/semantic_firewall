package actiontest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitIn returns a function that runs git in dir and returns its trimmed
// output.
func gitIn(t *testing.T, dir string) func(args ...string) string {
	return func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
}

// commitsRepo makes a repository on branch main with one commit per map (a
// nil content deletes the file, "symlink:<target>" makes a link) and
// returns it with the commits' hashes.
func commitsRepo(t *testing.T, commits ...map[string]*string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	git := gitIn(t, dir)
	git("init", "-q", "-b", "main")
	var shas []string
	for _, c := range commits {
		for name, src := range c {
			p := filepath.Join(dir, name)
			os.Remove(p)
			if src == nil {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			var err error
			if target, ok := strings.CutPrefix(*src, "symlink:"); ok {
				err = os.Symlink(target, p)
			} else {
				err = os.WriteFile(p, []byte(*src), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		git("add", "-A")
		git("commit", "-q", "-m", "c")
		shas = append(shas, git("rev-parse", "HEAD"))
	}
	return dir, shas
}

const (
	guardedSrc = "package p\n\nimport \"os/exec\"\n\nfunc Run(user, c string) error {\n\tif user != \"admin\" {\n\t\treturn nil\n\t}\n\treturn exec.Command(c).Run()\n}\n"
	changedSrc = "package p\n\nimport (\n\t\"net\"\n\t\"os/exec\"\n)\n\nfunc Run(user, c string) error {\n\tnet.Dial(\"tcp\", \"203.0.113.7:443\")\n\treturn exec.Command(c).Run()\n}\n"
	zeroSHA    = "0000000000000000000000000000000000000000"
	goneSHA    = "1111111111111111111111111111111111111111"
)

func baseFiles() map[string]*string {
	return map[string]*string{"go.mod": str(gomod), "p/p.go": str(guardedSrc), "q/q.go": str("package q\n\nfunc Q() int { return 1 }\n")}
}

// upstream makes a bare repository whose main is the base commit and whose
// pr branch changes p/p.go, and returns it with both commits.
func upstream(t *testing.T) (up, base, pr string) {
	t.Helper()
	work, shas := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)})
	git := gitIn(t, work)
	git("branch", "pr", shas[1])
	git("reset", "-q", "--hard", shas[0])
	up = filepath.Join(t.TempDir(), "up.git")
	gitIn(t, work)("clone", "-q", "--bare", work, up)
	return up, shas[0], shas[1]
}

func cloneOf(t *testing.T, up string) (string, func(...string) string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "clone")
	gitIn(t, filepath.Dir(dir))("clone", "-q", "file://"+up, dir)
	return dir, gitIn(t, dir)
}

// diffedFiles returns the new_file of each diff result.
func diffedFiles(t *testing.T, res actionRun) []string {
	t.Helper()
	var entries []diffEntry
	if err := json.Unmarshal([]byte(res.outputs["result"]), &entries); err != nil {
		t.Fatalf("result is not a JSON array: %v\n%s", err, res.log)
	}
	var files []string
	for _, e := range entries {
		files = append(files, e.NewFile)
	}
	return files
}

func diffMode(extra map[string]string) map[string]string {
	in := map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "INPUT_FAIL_ON_ALERT": "false"}
	for k, v := range extra {
		in[k] = v
	}
	return in
}

// The base each event compares with: every route that resolves one must
// analyze the change to p/p.go.
func TestActionBaseResolves(t *testing.T) {
	requireTools(t)
	q2 := map[string]*string{"q/q.go": str("package q\n\nfunc Q() int { return 2 }\n")}

	cases := map[string]func(t *testing.T) (string, map[string]string){
		"push, two commits": func(t *testing.T) (string, map[string]string) {
			repo, shas := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)}, q2)
			return repo, map[string]string{"GITHUB_EVENT_BEFORE": shas[0]}
		},
		// HEAD^ alone would see only q/q.go.
		"push of a new branch": func(t *testing.T) (string, map[string]string) {
			up, _, pr := upstream(t)
			clone, git := cloneOf(t, up)
			git("checkout", "-q", "--detach", pr)
			os.WriteFile(filepath.Join(clone, "q/q.go"), []byte(*q2["q/q.go"]), 0o644)
			git("commit", "-qam", "q")
			return clone, map[string]string{"GITHUB_EVENT_BEFORE": zeroSHA, "DEFAULT_BRANCH": "main"}
		},
		"force push, before gone": func(t *testing.T) (string, map[string]string) {
			up, _, pr := upstream(t)
			clone, git := cloneOf(t, up)
			git("checkout", "-q", "--detach", pr)
			return clone, map[string]string{"GITHUB_EVENT_BEFORE": goneSHA, "DEFAULT_BRANCH": "main"}
		},
		// GitHub's merge commit: the first parent is the base, with no fetch.
		"pull request merge commit": func(t *testing.T) (string, map[string]string) {
			up, base, pr := upstream(t)
			clone, git := cloneOf(t, up)
			git("checkout", "-q", "--detach", base)
			git("merge", "-q", "--no-ff", "--no-edit", pr)
			git("remote", "set-url", "origin", "/nonexistent")
			return clone, map[string]string{"GITHUB_EVENT_NAME": "pull_request", "PR_BASE_SHA": base, "PR_HEAD_SHA": pr}
		},
		"pull request head": func(t *testing.T) (string, map[string]string) {
			up, base, pr := upstream(t)
			clone, git := cloneOf(t, up)
			git("checkout", "-q", "--detach", pr)
			return clone, map[string]string{"GITHUB_EVENT_NAME": "pull_request", "PR_BASE_SHA": base, "PR_HEAD_SHA": pr}
		},
		// A fork checked out as origin, whose main already holds the
		// change: the base still comes from the event.
		"pull request head, fork as origin": func(t *testing.T) (string, map[string]string) {
			repo, shas := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)}, q2)
			fork := filepath.Join(t.TempDir(), "fork.git")
			gitIn(t, repo)("clone", "-q", "--bare", repo, fork)
			gitIn(t, fork)("update-ref", "refs/heads/main", shas[1])
			gitIn(t, repo)("remote", "add", "origin", fork)
			gitIn(t, repo)("fetch", "-q", "origin")
			gitIn(t, repo)("checkout", "-q", "--detach", shas[2])
			return repo, map[string]string{"GITHUB_EVENT_NAME": "pull_request_target", "PR_BASE_SHA": shas[0], "PR_HEAD_SHA": shas[2]}
		},
		// A merge whose second parent is the head, but whose first is not
		// the event's base, is not GitHub's merge commit.
		"pull request, merge onto another commit": func(t *testing.T) (string, map[string]string) {
			repo, shas := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)})
			git := gitIn(t, repo)
			git("checkout", "-q", "-b", "pr", shas[1])
			os.WriteFile(filepath.Join(repo, "q/q.go"), []byte(*q2["q/q.go"]), 0o644)
			git("commit", "-qam", "q")
			pr := git("rev-parse", "HEAD")
			git("checkout", "-q", "--detach", shas[1])
			git("merge", "-q", "--no-ff", "--no-edit", pr)
			return repo, map[string]string{"GITHUB_EVENT_NAME": "pull_request", "PR_BASE_SHA": shas[0], "PR_HEAD_SHA": pr}
		},
		// Without credentials the fetch fails; the checkout's copy of the
		// default branch serves.
		"push of a new branch, default branch not fetchable": func(t *testing.T) (string, map[string]string) {
			up, _, pr := upstream(t)
			clone, git := cloneOf(t, up)
			git("checkout", "-q", "--detach", pr)
			git("remote", "set-url", "origin", "/nonexistent")
			return clone, map[string]string{"GITHUB_EVENT_BEFORE": zeroSHA, "DEFAULT_BRANCH": "main"}
		},
		"merge group": func(t *testing.T) (string, map[string]string) {
			repo, shas := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)}, q2)
			return repo, map[string]string{"GITHUB_EVENT_NAME": "merge_group", "MG_BASE_SHA": shas[0], "MG_HEAD_SHA": shas[2]}
		},
		// The change's own files can't stand in for the Action's.
		"change adds the Action's old scratch paths": func(t *testing.T) (string, map[string]string) {
			repo, shas := commitsRepo(t, baseFiles(), map[string]*string{
				"p/p.go":               str(changedSrc),
				".sfw_diff_stream.bin": str("symlink:/dev/null"),
			})
			return repo, map[string]string{"GITHUB_EVENT_BEFORE": shas[0]}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			repo, in := setup(t)
			res := runAction(t, repo, diffMode(in))
			if res.exitCode != 0 {
				t.Fatalf("exit %d:\n%s", res.exitCode, res.log)
			}
			files := diffedFiles(t, res)
			found := false
			for _, f := range files {
				found = found || f == "p/p.go"
			}
			if !found {
				t.Errorf("diffed %v; want p/p.go among them:\n%s", files, res.log)
			}
		})
	}
}

// A base that can't be resolved fails the prepare step, rather than
// comparing nothing or the wrong commits.
func TestActionBaseFailsClosed(t *testing.T) {
	requireTools(t)
	cases := map[string]struct {
		setup func(t *testing.T) (string, map[string]string)
		want  string
	}{
		"push, before gone, no remote": {func(t *testing.T) (string, map[string]string) {
			repo, _ := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)})
			return repo, map[string]string{"GITHUB_EVENT_BEFORE": goneSHA, "DEFAULT_BRANCH": "main"}
		}, "default branch cannot be fetched"},
		"pull request base unfetchable": {func(t *testing.T) (string, map[string]string) {
			up, _, pr := upstream(t)
			clone, git := cloneOf(t, up)
			git("checkout", "-q", "--detach", pr)
			git("remote", "set-url", "origin", "/nonexistent")
			return clone, map[string]string{"GITHUB_EVENT_NAME": "pull_request", "PR_BASE_SHA": goneSHA, "PR_HEAD_SHA": pr}
		}, "Cannot fetch the pull request's base commit"},
		// pull_request_target checks out the base by default, not the PR.
		"pull request target, base checked out": {func(t *testing.T) (string, map[string]string) {
			up, base, pr := upstream(t)
			clone, _ := cloneOf(t, up)
			return clone, map[string]string{"GITHUB_EVENT_NAME": "pull_request_target", "PR_BASE_SHA": base, "PR_HEAD_SHA": pr}
		}, "HEAD does not contain the pull request head"},
		"pull request without head": {func(t *testing.T) (string, map[string]string) {
			repo, shas := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)})
			return repo, map[string]string{"GITHUB_EVENT_NAME": "pull_request", "PR_BASE_SHA": shas[0]}
		}, "no pull request head commit"},
		"pull request without base": {func(t *testing.T) (string, map[string]string) {
			repo, shas := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)})
			return repo, map[string]string{"GITHUB_EVENT_NAME": "pull_request", "PR_HEAD_SHA": shas[1]}
		}, "no pull request base commit"},
		"merge group head mismatch": {func(t *testing.T) (string, map[string]string) {
			repo, shas := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)}, map[string]*string{"q/q.go": str("package q\n")})
			return repo, map[string]string{"GITHUB_EVENT_NAME": "merge_group", "MG_BASE_SHA": shas[0], "MG_HEAD_SHA": shas[1]}
		}, "HEAD is not the merge group head"},
		// The default branch already holds the push, so it can't tell
		// what the push changed.
		"force push to the default branch, before gone": {func(t *testing.T) (string, map[string]string) {
			up, _, pr := upstream(t)
			gitIn(t, up)("update-ref", "refs/heads/main", pr)
			clone, _ := cloneOf(t, up)
			return clone, map[string]string{"GITHUB_EVENT_BEFORE": goneSHA, "DEFAULT_BRANCH": "main"}
		}, "The base is HEAD itself"},
		"other event, single commit": {func(t *testing.T) (string, map[string]string) {
			repo, _ := commitsRepo(t, baseFiles())
			return repo, map[string]string{"GITHUB_EVENT_NAME": "workflow_dispatch"}
		}, "HEAD has no parent"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			repo, in := c.setup(t)
			res, prepOK := runSteps(t, repo, diffMode(in))
			if prepOK || !strings.Contains(res.log, "::error::") || !strings.Contains(res.log, c.want) {
				t.Errorf("prep ok %v, exit %d; want it to fail with %q:\n%s", prepOK, res.exitCode, c.want, res.log)
			}
		})
	}
}

// run-sfw refuses diff, audit and deps without the base prep resolved.
func TestActionRunNeedsPrep(t *testing.T) {
	requireTools(t)
	repo, _ := commitsRepo(t, baseFiles(), map[string]*string{"p/p.go": str(changedSrc)})
	for _, mode := range []string{"diff", "audit", "deps"} {
		cmd := exec.Command("bash", "-c", stepScript(t, "run-sfw"))
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "INPUT_MODE="+mode, "INPUT_PATH=.", "GITHUB_OUTPUT="+filepath.Join(t.TempDir(), "out"),
			"RUNNER_TEMP="+t.TempDir(), "PREP_BASE_SHA=", "PREP_WORKTREE_DIR=", "PREP_PAIRS_FILE=", "PREP_PAIR_COUNT=", "PREP_GITLINKS_FILE=", "PREP_GITLINK_COUNT=")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "did not resolve a base") {
			t.Errorf("%s: err %v; want a failure naming the missing base:\n%s", mode, err, out)
		}
	}
}

// A push that adds no commits to the default branch (a tag, a new branch
// at main's tip) has nothing to compare, and passes.
func TestActionPushOfNothingNew(t *testing.T) {
	requireTools(t)
	up, _, pr := upstream(t)
	gitIn(t, up)("update-ref", "refs/heads/main", pr)
	clone, git := cloneOf(t, up)
	git("checkout", "-q", "--detach", pr)
	for _, mode := range []string{"diff", "audit"} {
		res := runAction(t, clone, map[string]string{"INPUT_MODE": mode, "INPUT_PATH": ".", "GITHUB_EVENT_BEFORE": zeroSHA, "DEFAULT_BRANCH": "main"})
		if res.exitCode != 0 || res.outputs["pair_count"] != "0" {
			t.Errorf("%s: exit %d, pair_count %q; want 0, 0:\n%s", mode, res.exitCode, res.outputs["pair_count"], res.log)
		}
	}
}
