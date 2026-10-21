package actiontest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const authSrc = "package p\n\nimport \"crypto/hmac\"\n\nfunc Valid(a, b []byte) bool { return hmac.Equal(a, b) }\n"

// A file that leaves the build, whatever git calls the change, is compared
// with nothing, so its checks read as removed. A rename within a directory
// stays one pair.
func TestActionDiffModeFileLeavesBuild(t *testing.T) {
	requireTools(t)
	base := map[string]string{
		"go.mod":    gomod,
		"p/auth.go": authSrc,
		"p/p.go":    "package p\n\nfunc P() int { return 1 }\n",
	}
	moves := map[string]string{
		"deleted":             "",
		"to a test file":      "p/auth_test.go",
		"to a backup":         "p/auth.go.bak",
		"to upper-case .GO":   "p/auth.GO",
		"into vendor":         "vendor/x/auth.go",
		"into testdata":       "p/testdata/auth.go",
		"into an _ directory": "p/_old/auth.go",
		"into a . directory":  "p/.old/auth.go",
		"to another package":  "attic/auth.go",
	}
	for name, dst := range moves {
		t.Run(name, func(t *testing.T) {
			changes := map[string]*string{"p/auth.go": nil}
			if dst != "" {
				changes[dst] = str(authSrc)
			}
			repo := gitRepo(t, base, changes)
			res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "INPUT_FAIL_ON_ALERT": "false"})
			var entries []diffEntry
			if err := json.Unmarshal([]byte(res.outputs["result"]), &entries); err != nil {
				t.Fatalf("result is not a JSON array: %v\n%s", err, res.log)
			}
			for _, e := range entries {
				if e.OldFile == "p/auth.go" && e.NewFile == "/dev/null" && e.Summary.HighRisk > 0 {
					return
				}
			}
			t.Errorf("no high-risk removal of p/auth.go in %+v:\n%s", entries, res.log)
		})
	}

	t.Run("renamed within its directory", func(t *testing.T) {
		repo := gitRepo(t, base, map[string]*string{"p/auth.go": nil, "p/check.go": str(authSrc)})
		res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": "."})
		var entries []diffEntry
		if err := json.Unmarshal([]byte(res.outputs["result"]), &entries); err != nil {
			t.Fatalf("result is not a JSON array: %v\n%s", err, res.log)
		}
		if res.exitCode != 0 || len(entries) != 1 || entries[0].OldFile != "p/auth.go" ||
			entries[0].NewFile != "p/check.go" || entries[0].Summary.HighRisk != 0 {
			t.Errorf("exit %d, entries %+v; want one clean auth.go -> check.go pair:\n%s", res.exitCode, entries, res.log)
		}
	})
}

// Audit mode analyzes the same pairs: a deletion is audited, not passed
// as "No Go files changed".
func TestActionAuditModeDeletedFile(t *testing.T) {
	requireTools(t)
	repo := gitRepo(t, map[string]string{"go.mod": gomod, "p/auth.go": authSrc, "p/p.go": "package p\n"},
		map[string]*string{"p/auth.go": nil})
	res := runAction(t, repo, map[string]string{"INPUT_MODE": "audit", "INPUT_PATH": "."})
	if strings.Contains(res.outputs["result"], "No Go files changed") || strings.Contains(res.outputs["result"], "(0 file(s)") {
		t.Errorf("audit skipped the deleted file: %q\n%s", res.outputs["result"], res.log)
	}
}

// git quotes unusual names unless asked for -z; a quoted name must not slip
// past the .go test.
func TestActionDiffModeUnusualName(t *testing.T) {
	requireTools(t)
	repo := gitRepo(t, map[string]string{"go.mod": gomod, "p/p.go": "package p\n"},
		map[string]*string{"p/é_generated.go": str("package p\n\nimport \"net\"\n\nfunc E(a string) { net.Dial(\"tcp\", a) }\n")})
	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "INPUT_FAIL_ON_ALERT": "false"})
	var entries []diffEntry
	if err := json.Unmarshal([]byte(res.outputs["result"]), &entries); err != nil {
		t.Fatalf("result is not a JSON array: %v\n%s", err, res.log)
	}
	if len(entries) != 1 || entries[0].NewFile != "p/é_generated.go" || entries[0].Summary.HighRisk == 0 {
		t.Errorf("entries %+v; want the high-risk p/é_generated.go:\n%s", entries, res.log)
	}
}

// A .go link compiles its target: a change to the target alone, whatever
// its name, is a change to the link.
func TestActionDiffModeLinkTargetChanged(t *testing.T) {
	requireTools(t)
	repo, shas := commitsRepo(t, map[string]*string{
		"go.mod":     str(gomod),
		"p/impl.txt": str(authSrc),
		"p/auth.go":  str("symlink:impl.txt"),
		"p/p.go":     str("package p\n"),
	}, map[string]*string{"p/impl.txt": str("package p\n\nfunc Valid(a, b []byte) bool { return true }\n")})
	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "GITHUB_EVENT_BEFORE": shas[0]})
	files := diffedFiles(t, res)
	if res.exitCode == 0 || len(files) != 1 || files[0] != "p/auth.go" || res.outputs["high-risk-changes"] != "1" {
		t.Errorf("exit %d, diffed %v, high risk %q; want a failing high-risk p/auth.go:\n%s", res.exitCode, files, res.outputs["high-risk-changes"], res.log)
	}
}

// A submodule's change can't be read file by file: diff mode counts it as
// a high-risk change, and audit mode fails.
func TestActionSubmoduleChanged(t *testing.T) {
	requireTools(t)
	repo, _ := commitsRepo(t, map[string]*string{"go.mod": str(gomod), "p/p.go": str("package p\n")})
	git := gitIn(t, repo)
	setLink := func(sha string) {
		git("update-index", "--add", "--cacheinfo", "160000,"+sha+",third_party/lib")
		git("commit", "-q", "-m", "lib "+sha[:7])
	}
	setLink("1111111111111111111111111111111111111111")
	before := git("rev-parse", "HEAD")
	setLink("2222222222222222222222222222222222222222")

	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "GITHUB_EVENT_BEFORE": before})
	if res.exitCode == 0 || res.outputs["high-risk-changes"] != "1" || !strings.Contains(res.log, "::error file=third_party/lib::Submodule changed") {
		t.Errorf("diff: exit %d, high risk %q; want a failure and an annotation:\n%s", res.exitCode, res.outputs["high-risk-changes"], res.log)
	}
	res = runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "GITHUB_EVENT_BEFORE": before, "INPUT_FAIL_ON_ALERT": "false"})
	if res.exitCode != 0 || !strings.Contains(res.log, "::warning file=third_party/lib::") {
		t.Errorf("diff, fail-on-alert false: exit %d; want 0 and a warning:\n%s", res.exitCode, res.log)
	}
	res = runAction(t, repo, map[string]string{"INPUT_MODE": "audit", "INPUT_PATH": ".", "GITHUB_EVENT_BEFORE": before})
	if res.exitCode == 0 || res.outputs["audit-verdict"] != "FAIL" {
		t.Errorf("audit: exit %d, verdict %q; want FAIL:\n%s", res.exitCode, res.outputs["audit-verdict"], res.log)
	}
}

// The change's own .gitmodules can't hide a submodule from the diff.
func TestActionSubmoduleIgnoreAll(t *testing.T) {
	requireTools(t)
	repo, _ := commitsRepo(t, map[string]*string{"go.mod": str(gomod), "p/p.go": str("package p\n")})
	git := gitIn(t, repo)
	modules := "[submodule \"lib\"]\n\tpath = third_party/lib\n\turl = ./lib\n"
	os.WriteFile(filepath.Join(repo, ".gitmodules"), []byte(modules), 0o644)
	git("add", ".gitmodules")
	git("update-index", "--add", "--cacheinfo", "160000,1111111111111111111111111111111111111111,third_party/lib")
	git("commit", "-q", "-m", "lib")
	before := git("rev-parse", "HEAD")
	os.WriteFile(filepath.Join(repo, ".gitmodules"), []byte(modules+"\tignore = all\n"), 0o644)
	git("add", ".gitmodules")
	git("update-index", "--cacheinfo", "160000,2222222222222222222222222222222222222222,third_party/lib")
	git("commit", "-q", "-m", "lib bump")
	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "GITHUB_EVENT_BEFORE": before})
	if res.exitCode == 0 || res.outputs["gitlink_count"] != "1" {
		t.Errorf("exit %d, gitlink_count %q; want the bump counted and a failure:\n%s", res.exitCode, res.outputs["gitlink_count"], res.log)
	}
}

// A go.mod renamed away is a module change, under its old name.
func TestActionModFileRenamedAway(t *testing.T) {
	requireTools(t)
	repo := gitRepo(t, map[string]string{"go.mod": gomod, "sub/go.mod": "module example.com/m/sub\n\ngo 1.22\n", "p/p.go": "package p\n"},
		map[string]*string{"sub/go.mod": nil, "sub/go.mod.bak": str("module example.com/m/sub\n\ngo 1.22\n")})
	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": "."})
	if res.outputs["has_mod_changes"] != "true" {
		t.Errorf("has_mod_changes %q; want true:\n%s", res.outputs["has_mod_changes"], res.log)
	}
}
