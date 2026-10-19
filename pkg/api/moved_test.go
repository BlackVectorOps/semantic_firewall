package api_test

import (
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// fetchExec is the old version of the moved-capability cases: Fetch calls
// os/exec directly.
const fetchExec = `package p
import "os/exec"
func Fetch(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`

// guardedFetch is fetchExec with the call under a condition.
const guardedFetch = `package p
import "os/exec"
func Fetch(ref string, allowed bool) error {
	if !allowed { return nil }
	return exec.Command("git", "fetch", ref).Run()
}
`

// A capability call extracted from an existing function into a new helper
// is labelled MovedCapability and not charged. Anything a move could smuggle
// in with it -- a new caller, a dropped guard, a new capability, a helper
// that escapes as a value -- keeps the helper's full score.
func TestDiffRisk_MovedCapability(t *testing.T) {
	cases := []struct {
		name, oldSrc, newSrc, fn, label string
		high                            bool
		noMove                          bool // fn must not be labelled MovedCapability
	}{
		{name: "extracted into a helper", fn: "run", high: false,
			label:  "MovedCapability((os/exec.Cmd).Run<-Fetch,os/exec.Command<-Fetch)",
			oldSrc: fetchExec,
			newSrc: `package p
import "os/exec"
func Fetch(ref string) error { return run("git", "fetch", ref) }
func run(args ...string) error { return exec.Command(args[0], args[1:]...).Run() }
`},
		{name: "two calls from one caller name it once", fn: "run", high: false,
			label: "MovedCapability((os/exec.Cmd).Run<-Fetch,os/exec.Command<-Fetch)",
			oldSrc: `package p
import "os/exec"
func Fetch(a, b string) error {
	if err := exec.Command("git", "fetch", a).Run(); err != nil { return err }
	return exec.Command("git", "fetch", b).Run()
}
`,
			newSrc: `package p
import "os/exec"
func Fetch(a, b string) error {
	if err := run(a); err != nil { return err }
	return run(b)
}
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "moved out of two callers", fn: "git", high: false,
			label: "os/exec.Command<-Fetch|Pull",
			oldSrc: `package p
import "os/exec"
func Fetch() error { return exec.Command("git", "fetch").Run() }
func Pull() error { return exec.Command("git", "pull").Run() }
`,
			newSrc: `package p
import "os/exec"
func Fetch() error { return git("fetch") }
func Pull() error { return git("pull") }
func git(arg string) error { return exec.Command("git", arg).Run() }
`},
		{name: "guard stays around the call to the helper", fn: "run", high: false,
			label:  "MovedCapability(",
			oldSrc: guardedFetch,
			newSrc: `package p
import "os/exec"
func Fetch(ref string, allowed bool) error {
	if !allowed { return nil }
	return run(ref)
}
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "guard moves into the helper", fn: "run", high: false,
			label:  "MovedCapability(",
			oldSrc: guardedFetch,
			newSrc: `package p
import "os/exec"
func Fetch(ref string, allowed bool) error { return run(ref, allowed) }
func run(ref string, allowed bool) error {
	if !allowed { return nil }
	return exec.Command("git", "fetch", ref).Run()
}
`},
		{name: "guard dropped in the move", fn: "run", high: true, noMove: true,
			label:  "Capability+exec(",
			oldSrc: guardedFetch,
			newSrc: `package p
import "os/exec"
func Fetch(ref string, allowed bool) error { _ = allowed; return run(ref) }
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "helper gains a caller that never made the call", fn: "run", high: true, noMove: true,
			label: "Capability+exec(",
			oldSrc: fetchExec + `func Status() string { return "ok" }
`,
			newSrc: `package p
import "os/exec"
func Fetch(ref string) error { return run(ref) }
func Status() string { run("--all"); return "ok" }
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "helper escapes as a value", fn: "run", high: true, noMove: true,
			label:  "Capability+exec(",
			oldSrc: fetchExec,
			newSrc: `package p
import "os/exec"
var Hooks = []func(string) error{run}
func Fetch(ref string) error { return run(ref) }
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "exported helper", fn: "Run", high: true, noMove: true,
			label:  "Capability+exec(",
			oldSrc: fetchExec,
			newSrc: `package p
import "os/exec"
func Fetch(ref string) error { return Run(ref) }
func Run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "method helper", fn: "(*T).run", high: true, noMove: true,
			label: "Capability+exec(",
			oldSrc: `package p
import "os/exec"
type T struct{}
func (t *T) Fetch(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`,
			newSrc: `package p
import "os/exec"
type T struct{}
func (t *T) Fetch(ref string) error { return t.run(ref) }
func (t *T) run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "caller keeps its own call", fn: "run", high: true, noMove: true,
			label:  "Capability+exec(",
			oldSrc: fetchExec,
			newSrc: `package p
import "os/exec"
func Fetch(ref string) error {
	if err := exec.Command("git", "fetch", ref).Run(); err != nil { return err }
	return run(ref)
}
func run(ref string) error { return exec.Command("git", "gc", ref).Run() }
`},
		{name: "helper also reaches a new class", fn: "run", high: true,
			label:  "Capability+network(net.Dial)",
			oldSrc: fetchExec,
			newSrc: `package p
import ("net";"os/exec")
func Fetch(ref string) error { return run(ref) }
func run(ref string) error {
	net.Dial("tcp", ref)
	return exec.Command("git", "fetch", ref).Run()
}
`},
		{name: "helper started as a goroutine flags the caller", fn: "Fetch", high: true, noMove: true,
			label:  "AddedGoroutine",
			oldSrc: fetchExec,
			newSrc: `package p
import "os/exec"
func Fetch(ref string) error { go run(ref); return nil }
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "old caller past the guard analysis", fn: "run", high: true, noMove: true,
			label: "Capability+exec(",
			oldSrc: "package p\nimport \"os/exec\"\nfunc Fetch(ref string, allowed bool) error {\n\tn := 0\n" +
				strings.Repeat("\tif allowed { n++ }\n", 1100) +
				"\t_ = n\n\tif !allowed { return nil }\n\treturn exec.Command(\"git\", \"fetch\", ref).Run()\n}\n",
			newSrc: `package p
import "os/exec"
func Fetch(ref string, allowed bool) error { return run(ref) }
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
		{name: "new caller past the guard analysis", fn: "run", high: true, noMove: true,
			label:  "Capability+exec(",
			oldSrc: guardedFetch,
			newSrc: "package p\nimport \"os/exec\"\nfunc Fetch(ref string, allowed bool) error {\n\tn := 0\n" +
				strings.Repeat("\tif allowed { n++ }\n", 1100) +
				"\t_ = n\n\tif !allowed { return nil }\n\treturn run(ref)\n}\n" +
				"func run(ref string) error { return exec.Command(\"git\", \"fetch\", ref).Run() }\n"},
		{name: "helper never called", fn: "run", high: true, noMove: true,
			label:  "Capability+exec(",
			oldSrc: fetchExec,
			newSrc: `package p
import "os/exec"
func Fetch(ref string) error { return nil }
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := findFunc(t, diffSources(t, c.oldSrc, c.newSrc), c.fn)
			if !strings.Contains(f.TopologyDelta, c.label) {
				t.Errorf("%s: delta %q; want it to contain %q", c.fn, f.TopologyDelta, c.label)
			}
			if high := f.RiskScore >= models.RiskScoreHigh; high != c.high {
				t.Errorf("%s: risk %d (delta %q); want high-risk %v", c.fn, f.RiskScore, f.TopologyDelta, c.high)
			}
			if !c.high && strings.Contains(f.TopologyDelta, "Capability+") {
				t.Errorf("%s: delta %q charges a moved capability", c.fn, f.TopologyDelta)
			}
			if c.noMove && strings.Contains(f.TopologyDelta, "MovedCapability") {
				t.Errorf("%s: delta %q labels a capability moved that was not", c.fn, f.TopologyDelta)
			}
		})
	}
}

// A moved target's class counts as one the helper already reached, so a new
// target of that class in the helper adds 5, as it would have in the caller,
// not the 30 of a newly reached exec class.
func TestDiffRisk_MovedCapabilityKeepsClass(t *testing.T) {
	f := findFunc(t, diffSources(t, fetchExec, `package p
import ("os";"os/exec")
func Fetch(ref string) error { return run(ref) }
func run(ref string) error {
	os.StartProcess("/bin/true", nil, &os.ProcAttr{})
	return exec.Command("git", "fetch", ref).Run()
}
`), "run")
	if !strings.Contains(f.TopologyDelta, "MovedCapability(") || !strings.Contains(f.TopologyDelta, "Capability+exec(os.StartProcess)") {
		t.Errorf("run: delta %q; want MovedCapability and Capability+exec(os.StartProcess)", f.TopologyDelta)
	}
	if want := models.BaseRiskAddedFunc + 5; f.RiskScore != want {
		t.Errorf("run: risk %d (delta %q); want %d", f.RiskScore, f.TopologyDelta, want)
	}
}

// A dependency that extracts a capability call into a helper is not given
// the move: deps diff leaves it to its reach analysis, so the helper keeps
// the new-capability label.
func TestDepsDiff_MovedCapabilityNotApplied(t *testing.T) {
	imports := "\t_ \"example.com/gitx\"\n"
	deps := map[string]string{"example.com/gitx": "gitx"}
	oldDir := appTree(t, imports, deps, map[string]string{"lib/gitx/gitx.go": strings.Replace(fetchExec, "package p", "package gitx", 1)})
	newDir := appTree(t, imports, deps, map[string]string{"lib/gitx/gitx.go": `package gitx
import "os/exec"
func Fetch(ref string) error { return run(ref) }
func run(ref string) error { return exec.Command("git", "fetch", ref).Run() }
`})
	m := findModule(t, depsDiff(t, oldDir, newDir), "example.com/gitx")
	for _, p := range m.Packages {
		for _, f := range p.Functions {
			if f.Function != "run" {
				continue
			}
			if strings.Contains(f.TopologyDelta, "MovedCapability") || !strings.Contains(f.TopologyDelta, "Capability+exec(") {
				t.Errorf("run: delta %q; want Capability+exec and no MovedCapability", f.TopologyDelta)
			}
			return
		}
	}
	t.Fatalf("run not reported in %+v", m.Packages)
}
