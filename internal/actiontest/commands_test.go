package actiontest

import (
	"strings"
	"testing"
)

// activeCommands returns the log lines the runner would take as workflow
// commands: lines starting with "::" once leading space is trimmed,
// skipping those between ::stop-commands::<token> and ::<token>::.
func activeCommands(log string) []string {
	var cmds []string
	stopped := ""
	for _, l := range strings.Split(log, "\n") {
		l = strings.TrimLeft(l, " \t")
		if stopped != "" {
			if l == "::"+stopped+"::" {
				stopped = ""
			}
			continue
		}
		if tok, ok := strings.CutPrefix(l, "::stop-commands::"); ok {
			stopped = tok
			continue
		}
		if strings.HasPrefix(l, "::") {
			cmds = append(cmds, l)
		}
	}
	return cmds
}

// A file name or message from the change can't start a workflow command of
// its own, in an annotation or in output the step prints.
func TestActionCommandsCannotBeInjected(t *testing.T) {
	requireTools(t)
	forged := "::error title=forged::forged"
	repo := gitRepo(t, map[string]string{"go.mod": gomod, "p/p.go": "package p\n"}, map[string]*string{
		// Not Go, so sfw reports an error naming the file.
		"p/x\n" + forged + "\n.go": str("not go\n" + forged + "\n"),
	})
	for _, mode := range []string{"diff", "check"} {
		res := runAction(t, repo, map[string]string{"INPUT_MODE": mode, "INPUT_PATH": ".", "INPUT_STRICT": "false"})
		for _, c := range activeCommands(res.log) {
			if strings.Contains(c, "forged") && !strings.HasPrefix(c, "::warning::") {
				t.Errorf("%s: injected command %q:\n%s", mode, c, res.log)
			}
		}
		if mode == "diff" && !strings.Contains(res.log, "%0A::error title=forged::forged%0A.go") {
			t.Errorf("diff: no escaped name in the annotation:\n%s", res.log)
		}
	}
}
