package actiontest

import (
	"strings"
	"testing"
)

// Diff mode fails on high-risk changes unless fail-on-alert is false, and
// annotates each one on its file.
func TestActionDiffModeGate(t *testing.T) {
	requireTools(t)
	repo := gitRepo(t, map[string]string{
		"go.mod":    gomod,
		"p/a.go":    "package p\n\nimport \"fmt\"\n\nfunc Handle(c string) { fmt.Println(c) }\n",
		"p/auth.go": authSrc,
		"q/q.go":    "package q\n\nfunc Q() int { return 1 }\n",
	}, map[string]*string{
		"p/a.go":    str("package p\n\nimport \"os/exec\"\n\nfunc Handle(c string) { exec.Command(c).Run() }\n"),
		"p/auth.go": nil,
		"q/q.go":    str("package q\n\nfunc Q() int { return 2 }\n"),
	})

	res := runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": "."})
	if res.exitCode == 0 || res.outputs["high-risk-changes"] != "2" || !strings.Contains(res.log, "::error::2 high-risk change(s)") {
		t.Errorf("default: exit %d, high-risk-changes %q; want a failure on 2:\n%s", res.exitCode, res.outputs["high-risk-changes"], res.log)
	}
	for _, want := range []string{"::error file=p/a.go::", "::error file=p/auth.go::"} {
		if !strings.Contains(res.log, want) {
			t.Errorf("default: no %q annotation:\n%s", want, res.log)
		}
	}

	res = runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "INPUT_FAIL_ON_ALERT": "false"})
	if res.exitCode != 0 || !strings.Contains(res.log, "::warning::2 high-risk change(s)") || !strings.Contains(res.log, "::warning file=p/a.go::") {
		t.Errorf("fail-on-alert false: exit %d; want 0 and warnings:\n%s", res.exitCode, res.log)
	}

	// Anything but true or false fails, rather than reading as off.
	res = runAction(t, repo, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": ".", "INPUT_FAIL_ON_ALERT": "False"})
	if res.exitCode == 0 || !strings.Contains(res.log, "fail-on-alert must be true or false") {
		t.Errorf("fail-on-alert False: exit %d; want a failure naming the input:\n%s", res.exitCode, res.log)
	}

	// Low-risk changes pass with a count of 0.
	quiet := gitRepo(t, map[string]string{"go.mod": gomod, "q/q.go": "package q\n\nfunc Q() int { return 1 }\n"},
		map[string]*string{"q/q.go": str("package q\n\nfunc Q() int { return 2 }\n")})
	res = runAction(t, quiet, map[string]string{"INPUT_MODE": "diff", "INPUT_PATH": "."})
	if res.exitCode != 0 || res.outputs["high-risk-changes"] != "0" {
		t.Errorf("low risk: exit %d, high-risk-changes %q; want 0, 0:\n%s", res.exitCode, res.outputs["high-risk-changes"], res.log)
	}
}
