package actiontest

import (
	"encoding/json"
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
				if strings.HasSuffix(e.OldFile, "/p/auth.go") && e.NewFile == "/dev/null" && e.Summary.HighRisk > 0 {
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
		if res.exitCode != 0 || len(entries) != 1 || !strings.HasSuffix(entries[0].OldFile, "/p/auth.go") ||
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
