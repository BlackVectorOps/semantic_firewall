package topology_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
)

// functions compiles each source as its own package of one module, in a
// single load, and returns the function F of each.
//
// The sources can import a stub golang.org/x/crypto/ssh, and testmod/fake/ssh,
// a package of the same name that is not it.
func functions(t *testing.T, srcs ...string) []*ssa.Function {
	t.Helper()
	dir := t.TempDir()
	const sshStub = `package ssh

type HostKeyCallback func(hostname string) error

func InsecureIgnoreHostKey() HostKeyCallback { return nil }

func FixedHostKey() HostKeyCallback { return nil }

type Config struct{}

func (Config) InsecureIgnoreHostKey() HostKeyCallback { return nil }
`
	files := map[string]string{
		"go.mod":             "module testmod\n\ngo 1.23\n\nrequire golang.org/x/crypto v0.0.0\n\nreplace golang.org/x/crypto => ./xcrypto\n",
		"xcrypto/go.mod":     "module golang.org/x/crypto\n\ngo 1.23\n",
		"xcrypto/ssh/ssh.go": sshStub,
		"fake/ssh/ssh.go":    sshStub,
		"helper/helper.go":   "package helper\n\nimport (\"crypto/hmac\"; \"net/http\"; \"os\")\n\nfunc Same(a, b []byte) bool { return hmac.Equal(a, b) }\n\nfunc Die() { os.Exit(1) }\n\nfunc Cookie(v string) *http.Cookie { return &http.Cookie{Name: \"s\", Value: v, Secure: true} }\n\nfunc validName(s string) bool { return s != \"\" }\n\nfunc Process(s string) bool { return validName(s) }\n",
	}
	// helper is a root, so its functions have SSA bodies.
	patterns := []string{"./helper"}
	for i, src := range srcs {
		files[fmt.Sprintf("c%d/main.go", i)] = src
		patterns = append(patterns, fmt.Sprintf("./c%d", i))
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &packages.Config{
		Dir:  dir,
		Mode: packages.LoadAllSyntax,
		Env:  append(os.Environ(), "GO111MODULE=on", "GOPROXY=off", "CGO_ENABLED=0", "GOFLAGS="),
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("compilation errors in test sources")
	}
	prog, _, err := ir.BuildSSAFromPackages(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	fns := make([]*ssa.Function, len(srcs))
	for _, pkg := range pkgs {
		if pkg.PkgPath == "testmod/helper" {
			continue
		}
		var i int
		if _, err := fmt.Sscanf(pkg.PkgPath, "testmod/c%d", &i); err != nil || i < 0 || i >= len(srcs) {
			t.Fatalf("unexpected package %s", pkg.PkgPath)
		}
		fns[i] = prog.Package(pkg.Types).Func("F")
		if fns[i] == nil {
			t.Fatalf("no function F in case %d", i)
		}
	}
	return fns
}

// topologies is functions followed by ExtractTopology. Package paths in
// call target keys read "testmod", as if each case were the only one.
func topologies(t *testing.T, srcs ...string) []*topology.FunctionTopology {
	t.Helper()
	out := make([]*topology.FunctionTopology, len(srcs))
	for i, fn := range functions(t, srcs...) {
		tp := topology.ExtractTopology(fn)
		if tp == nil {
			t.Fatalf("no topology for F in case %d", i)
		}
		pkgPath := fn.Pkg.Pkg.Path()
		tp.CapabilityGuards = rekey(tp.CapabilityGuards, pkgPath)
		tp.Checks = rekey(tp.Checks, pkgPath)
		tp.MovedChecks = rekey(tp.MovedChecks, pkgPath)
		tp.HelperMovedChecks = rekey(tp.HelperMovedChecks, pkgPath)
		for k, vias := range tp.HelperMovedChecks {
			for j, via := range vias {
				vias[j] = strings.ReplaceAll(via, pkgPath, "testmod")
			}
			tp.HelperMovedChecks[k] = vias
		}
		for k, via := range tp.MovedChecks {
			tp.MovedChecks[k] = strings.ReplaceAll(via, pkgPath, "testmod")
		}
		out[i] = tp
	}
	return out
}

func rekey[V any](m map[string]V, pkgPath string) map[string]V {
	if m == nil {
		return nil
	}
	out := make(map[string]V, len(m))
	for k, v := range m {
		out[strings.ReplaceAll(k, pkgPath, "testmod")] = v
	}
	return out
}

// manyBranches returns a function F with n one-armed ifs (two blocks each),
// optionally one if-else (three blocks), and a final unconditional
// os.Remove: 1+2n blocks, or 4+2n with the if-else.
func manyBranches(ifElse bool, n int) string {
	var b strings.Builder
	b.WriteString("package main\nimport \"os\"\nfunc F(x int, p string) {\n")
	if ifElse {
		b.WriteString("\tif x < 0 { x++ } else { x-- }\n")
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\tif x == %d { x++ }\n", i)
	}
	b.WriteString("\tos.Remove(p)\n}\nfunc main() {}\n")
	return b.String()
}

func TestCapabilityGuards(t *testing.T) {
	cases := []struct {
		name, src string
		want      map[string]int
	}{
		{"unconditional", `package main
import "os"
func F(p string) { os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"one guard", `package main
import "os"
func F(p string, ok bool) {
	if ok { os.Remove(p) }
}
func main() {}`, map[string]int{"os.Remove": 1}},
		{"a guard whose branch reaches the call through other blocks", `package main
import "os"
func F(p string, ok, z bool) {
	if ok {
		if z { println() }
		os.Remove(p)
	}
}
func main() {}`, map[string]int{"os.Remove": 1}},
		{"a closure calling a capability is not the function's call", `package main
import "os"
func F(p string, ok bool) func() {
	if ok { os.Remove(p) }
	return func() { os.Remove(p) }
}
func main() {}`, map[string]int{"os.Remove": 1}},
		{"nested guards: only the innermost is direct", `package main
import "os"
func F(p string, a, b bool) {
	if a {
		if b { os.Remove(p) }
	}
}
func main() {}`, map[string]int{"os.Remove": 1}},
		{"either of two conditions", `package main
import "os"
func F(p string, a, b bool) {
	if a || b { os.Remove(p) }
}
func main() {}`, map[string]int{"os.Remove": 2}},
		{"early return", `package main
import ("errors";"os")
func F(p string, ok bool) error {
	if !ok { return errors.New("no") }
	return os.Remove(p)
}
func main() {}`, map[string]int{"os.Remove": 1}},
		{"loop condition is not a guard", `package main
import "os"
func F(ps []string) { for _, p := range ps { os.Remove(p) } }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"a branch counts once when both sides lead to the call", `package main
import ("log";"os")
func F(p string, ok, z bool) {
	if ok { return }
	log.Fatal("x") // the rest is dead code, but its branch still counts once
	if z { println() }
	os.Remove(p)
}
func main() {}`, map[string]int{"os.Remove": 1}},
		{"nested loop conditions are not guards", `package main
import "os"
func F(pss [][]string) { for _, ps := range pss { for i := 0; i < len(ps); i++ { os.Remove(ps[i]) } } }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"guard inside a loop counts", `package main
import "os"
func F(ps []string) { for _, p := range ps { if len(p) > 1 { os.Remove(p) } } }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"panic ends the function", `package main
import "os"
func F(p string, ok bool) { if !ok { panic("no") }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"log.Fatal ends the function", `package main
import ("log";"os")
func F(p string, ok bool) { if !ok { log.Fatal("no") }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"os.Exit ends the function", `package main
import "os"
func F(p string, ok bool) { if !ok { os.Exit(1) }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"Logger.Fatalf ends the function", `package main
import ("log";"os")
func F(l *log.Logger, p string, ok bool) { if !ok { l.Fatalf("no") }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"runtime.Goexit ends the function", `package main
import ("os";"runtime")
func F(p string, ok bool) { if !ok { runtime.Goexit() }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"other os and runtime calls return", `package main
import ("os";"runtime")
func F(p string, ok bool) {
	if !ok { os.Getpid() }
	if ok { runtime.GC() }
	os.Remove(p)
}
func main() {}`, map[string]int{"os.Remove": 0}},
		{"t.Fatal ends the function", `package main
import ("os";"testing")
func F(t *testing.T, p string, ok bool) { if !ok { t.Fatal("no") }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"t.Log returns", `package main
import ("os";"testing")
func F(t *testing.T, p string, ok bool) { if !ok { t.Log("no") }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"Logger.Printf returns", `package main
import ("log";"os")
func F(l *log.Logger, p string, ok bool) { if !ok { l.Printf("no") }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"an ordinary call does not end the function", `package main
import ("fmt";"os")
func F(p string, ok bool) { if !ok { fmt.Println("no") }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"fewest guards over all references", `package main
import "os"
func F(p string, ok bool) {
	if ok { os.Remove(p) }
	os.Remove(p + ".tmp")
}
func main() {}`, map[string]int{"os.Remove": 0}},
		{"switch case with two values", `package main
import "os"
func F(cmd, p string) {
	switch cmd {
	case "a":
	case "rm", "del": os.Remove(p)
	}
}
func main() {}`, map[string]int{"os.Remove": 2}},
		{"two targets", `package main
import ("net";"os")
func F(p string, ok bool) {
	net.Dial("tcp", p)
	if ok { os.Remove(p) }
}
func main() {}`, map[string]int{"net.Dial": 0, "os.Remove": 1}},
		{"the first branch of a for {} body is a guard", `package main
import "os"
func F(ps []string, ok bool) { i := 0; for { if ok { os.Remove(ps[i]) }; i++; if i >= len(ps) { return } } }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"a guard in a function that never returns", `package main
import "os"
func F(jobs <-chan string, allowed map[string]bool) {
	for { p := <-jobs; if len(p) == 0 { continue }; if allowed[p] { os.Remove(p) } }
}
func main() {}`, map[string]int{"os.Remove": 1}},
		{"a skip in a function that never returns is a guard", `package main
import "os"
func F(jobs <-chan string) { for { p := <-jobs; if len(p) == 0 { continue }; os.Remove(p) } }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"an unguarded call in a function that never returns", `package main
import "os"
func F(jobs <-chan string) { for { os.Remove(<-jobs) } }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"a loop that never ends behind a guard", `package main
import "os"
func F(jobs <-chan string, ok bool) { if !ok { return }; for { os.Remove(<-jobs) } }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"a constant condition is no guard", `package main
import "os"
func F(p string) { if true { os.Remove(p) } }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"a constant flag bypasses a guard", `package main
import "os"
const bypass = true
func F(p string, isAdmin bool) { if bypass || isAdmin { os.Remove(p) } }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"a constant flag that keeps a guard", `package main
import "os"
const strict = true
func F(p string, isAdmin bool) { if strict && !isAdmin { return }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"a call only in dead code", `package main
import "os"
func F(p string) { if false { os.Remove(p) } }
func main() {}`, map[string]int{}},
		{"the same call on both sides of a branch", `package main
import "os"
func F(p string, isAdmin bool) { if isAdmin { os.Remove(p) } else { os.Remove(p) } }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"calls under two branches that can both be skipped", `package main
import "os"
func F(p string, a, b bool) { if a { os.Remove(p) } else if b { os.Remove(p) } }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"a helper of the package that always exits", `package main
import "os"
func die(msg string) { println(msg); os.Exit(1) }
func F(p string, ok bool) { if !ok { die("forbidden") }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"two guarded targets", `package main
import ("net";"os")
func F(p string, a, b bool) { if a { net.Dial("tcp", p) }; if b { os.Remove(p) } }
func main() {}`, map[string]int{"net.Dial": 1, "os.Remove": 1}},
		{"a loop that ends before an unconditional call", `package main
import "os"
func F(p string, ok bool) { if ok { for i := 0; i < 3; i++ { println(i) } }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"a constant false alternative adds no way out", `package main
import "os"
const bypass = false
func F(p string, a bool) { if a || bypass { return }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 1}},
		{"a helper of another package that always exits is not followed", `package main
import ("os";"testmod/helper")
func F(p string, ok bool) { if !ok { helper.Die() }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 0}},
		{"a helper of the package that may return", `package main
import "os"
func warn(msg string, fatal bool) { if fatal { os.Exit(1) }; println(msg) }
func F(p string, ok bool) { if !ok { warn("forbidden", true) }; os.Remove(p) }
func main() {}`, map[string]int{"os.Remove": 0}},
	}
	srcs := make([]string, len(cases))
	for i, c := range cases {
		srcs[i] = c.src
	}
	srcs = append(srcs,
		"package main\nfunc F(a int) int { if a > 1 { return 2 }; return 1 }\nfunc main() {}",
		manyBranches(true, 998), manyBranches(false, 1001))
	tps := topologies(t, srcs...)
	for i, c := range cases {
		tp := tps[i]
		t.Run(c.name, func(t *testing.T) {
			got := tp.CapabilityGuards
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("CapabilityGuards = %v; want %v", got, c.want)
			}
		})
	}

	t.Run("no capability, no map", func(t *testing.T) {
		if g := tps[len(cases)].CapabilityGuards; g != nil {
			t.Errorf("CapabilityGuards = %v; want nil", g)
		}
	})
	t.Run("block limit", func(t *testing.T) {
		at, over := tps[len(cases)+1], tps[len(cases)+2]
		if at.BlockCount != 2000 || over.BlockCount != 2003 {
			t.Fatalf("fixtures have %d and %d blocks; want 2000 and 2003", at.BlockCount, over.BlockCount)
		}
		if want := map[string]int{"os.Remove": 0}; !reflect.DeepEqual(at.CapabilityGuards, want) {
			t.Errorf("at the limit: CapabilityGuards = %v; want %v", at.CapabilityGuards, want)
		}
		if over.CapabilityGuards != nil {
			t.Errorf("over the limit: CapabilityGuards = %v; want nil", over.CapabilityGuards)
		}
	})
}

func TestChecks(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"verification primitive", `package main
import "crypto/hmac"
func F(a, b []byte) bool { return hmac.Equal(a, b) }
func main() {}`, []string{"crypto/hmac.Equal"}},
		{"helper reaching a primitive", `package main
import "crypto/subtle"
func same(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
func F(a, b []byte) bool { return same(a, b) }
func main() {}`, []string{"testmod.same", "crypto/subtle.ConstantTimeCompare"}},
		{"helper three calls deep", `package main
import "crypto/hmac"
func h1(a, b []byte) bool { return h2(a, b) }
func h2(a, b []byte) bool { return h3(a, b) }
func h3(a, b []byte) bool { return hmac.Equal(a, b) }
func F(a, b []byte) bool { return h1(a, b) }
func main() {}`, []string{"testmod.h1", "crypto/hmac.Equal"}},
		{"helper four calls deep is too far", `package main
import "crypto/hmac"
func h1(a, b []byte) bool { return h2(a, b) }
func h2(a, b []byte) bool { return h3(a, b) }
func h3(a, b []byte) bool { return h4(a, b) }
func h4(a, b []byte) bool { return hmac.Equal(a, b) }
func F(a, b []byte) bool { return h1(a, b) }
func main() {}`, nil},
		{"a helper within reach after one out of reach", `package main
import "crypto/hmac"
func h1(a, b []byte) bool { return h2(a, b) }
func h2(a, b []byte) bool { return h3(a, b) }
func h3(a, b []byte) bool { return h4(a, b) }
func h4(a, b []byte) bool { return hmac.Equal(a, b) }
func F(a, b []byte) bool { return h1(a, b) && h3(a, b) }
func main() {}`, []string{"testmod.h3", "crypto/hmac.Equal"}},
		{"mutually recursive helpers reaching a primitive", `package main
import "crypto/hmac"
func even(a, b []byte, n int) bool { if n == 0 { return hmac.Equal(a, b) }; return odd(a, b, n-1) }
func odd(a, b []byte, n int) bool { return even(a, b, n-1) }
func F(a, b []byte) bool { return odd(a, b, 3) }
func main() {}`, []string{"testmod.odd", "crypto/hmac.Equal"}},
		{"result tested by errors.Is", `package main
import "errors"
var errBad = errors.New("bad")
func validate(u string) error { if u == "" { return errBad }; return nil }
func F(u string) int { if err := validate(u); errors.Is(err, errBad) { return 0 }; return 1 }
func main() {}`, []string{"testmod.validate"}},
		{"result tested by errors.As", `package main
import "errors"
type vErr struct{}
func (*vErr) Error() string { return "v" }
func validate(u string) error { if u == "" { return &vErr{} }; return nil }
func F(u string) bool { var e *vErr; return errors.As(validate(u), &e) }
func main() {}`, []string{"testmod.validate"}},
		{"errors.Is result discarded", `package main
import "errors"
var errBad = errors.New("bad")
func validate(u string) error { if u == "" { return errBad }; return nil }
func F(u string) { _ = errors.Is(validate(u), errBad) }
func main() {}`, nil},
		{"errors.Is counts toward the operation limit", `package main
import "errors"
var errBad = errors.New("bad")
func validate(u string) error { if u == "" { return errBad }; return nil }
func F(u string) bool { return !!!!errors.Is(validate(u), errBad) }
func main() {}`, nil},
		{"result as the errors.Is target", `package main
import "errors"
var errBad = errors.New("bad")
func validate(u string) error { if u == "" { return errBad }; return nil }
func F(u string) bool { return errors.Is(errBad, validate(u)) }
func main() {}`, nil},
		{"result passed to another errors function", `package main
import "errors"
var errBad = errors.New("bad")
func validate(u string) error { if u == "" { return errBad }; return nil }
func F(u string) bool { return errors.Unwrap(validate(u)) == nil }
func main() {}`, nil},
		{"result passed to a local Is", `package main
import "errors"
var errBad = errors.New("bad")
func validate(u string) error { if u == "" { return errBad }; return nil }
func Is(a, b error) bool { return a == b }
func F(u string) bool { return Is(validate(u), errBad) }
func main() {}`, nil},
		{"two helpers sharing a verifier", `package main
import "crypto/hmac"
func valid(a, b []byte) bool { return hmac.Equal(a, b) }
func h1(a, b []byte) bool { return valid(a, b) }
func h2(a, b []byte) bool { return valid(a, b) }
func F(a, b []byte) bool { return h1(a, b) && h2(a, b) }
func main() {}`, []string{"testmod.h1", "testmod.h2", "crypto/hmac.Equal"}},
		{"two helpers sharing a function that verifies nothing", `package main
func plain(a, b []byte) bool { return len(a) == len(b) }
func h1(a, b []byte) bool { return plain(a, b) }
func h2(a, b []byte) bool { return plain(a, b) }
func F(a, b []byte) bool { return h1(a, b) && h2(a, b) }
func main() {}`, nil},
		{"a helper in another package is not followed", `package main
import "testmod/helper"
func F(a, b []byte) bool { return helper.Same(a, b) }
func main() {}`, nil},
		{"recursive helper terminates", `package main
func loop(n int) bool { if n == 0 { return false }; return loop(n - 1) }
func F() bool { return loop(3) }
func main() {}`, nil},
		{"a helper whose result is unused checks nothing", `package main
import "crypto/subtle"
func same(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
func F(a, b []byte) { ok := same(a, b); println(ok) }
func main() {}`, nil},
		{"a helper with no result checks by failing", `package main
import "crypto/hmac"
func mustMatch(a, b []byte) { if !hmac.Equal(a, b) { panic("mismatch") } }
func F(a, b []byte) { mustMatch(a, b) }
func main() {}`, []string{"testmod.mustMatch", "crypto/hmac.Equal"}},
		{"a generic helper", `package main
import "crypto/hmac"
func same[T ~[]byte](a, b T) bool { return hmac.Equal(a, b) }
func F(a, b []byte) int { if !same(a, b) { return 0 }; return 1 }
func main() {}`, []string{"testmod.same", "crypto/hmac.Equal"}},
		{"a closure invoked on the spot is part of its parent", `package main
import "crypto/hmac"
func F(a, b []byte) bool { f := func() bool { return hmac.Equal(a, b) }; return f() }
func main() {}`, []string{"crypto/hmac.Equal"}},
		{"verification name deciding a branch", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string) int { if !authorize(u) { return 0 }; return 1 }
func main() {}`, []string{"testmod.authorize"}},
		{"verification name whose error decides a branch", `package main
import "errors"
func validate(u string) error { if u == "" { return errors.New("empty") }; return nil }
func F(u string) int { if err := validate(u); err != nil { return 0 }; return 1 }
func main() {}`, []string{"testmod.validate"}},
		{"verification name returned to the caller", `package main
func isAdmin(u string) bool { return u == "admin" }
func F(u string) bool { return isAdmin(u) }
func main() {}`, []string{"testmod.isAdmin"}},
		{"verification result only accumulated in a loop", `package main
func authorize(u string) bool { return u == "admin" }
func F(us []string) { var acc bool; for _, u := range us { acc = acc != authorize(u) }; println(acc) }
func main() {}`, nil},
		{"verification result four operations from a branch", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string) int { ok := !!!!authorize(u); if ok { return 1 }; return 0 }
func main() {}`, []string{"testmod.authorize"}},
		{"verification result five operations from a branch", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string) int { ok := !!!!!authorize(u); if ok { return 1 }; return 0 }
func main() {}`, nil},
		{"verification result through a tuple", `package main
func validate(u string) (int, error) { return len(u), nil }
func F(u string) int { if _, err := validate(u); err != nil { return 0 }; return 1 }
func main() {}`, []string{"testmod.validate"}},
		{"verification result through a short-circuit phi", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string) int { ok := u == "" || authorize(u); if ok { return 1 }; return 0 }
func main() {}`, []string{"testmod.authorize"}},
		{"verification result through conversions", `package main
type Decision bool
type Level int32
func authorize(u string) Decision { return u == "admin" }
func accessLevel(u string) Level { return Level(len(u)) }
func F(u string) int { if bool(authorize(u)) && int64(accessLevel(u)) > 2 { return 1 }; return 0 }
func main() {}`, []string{"testmod.accessLevel", "testmod.authorize"}},
		{"verification result through a dereference", `package main
func allowed(u string) *bool { b := u == "admin"; return &b }
func F(u string) int { if *allowed(u) { return 1 }; return 0 }
func main() {}`, []string{"testmod.allowed"}},
		{"verification returned under a defer", `package main
import "sync"
var mu sync.Mutex
func authorize(u string) error { return nil }
func F(u string) error { mu.Lock(); defer mu.Unlock(); return authorize(u) }
func main() {}`, []string{"testmod.authorize"}},
		{"verification stored in a named result", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string) (ok bool) { defer println(); ok = authorize(u); return }
func main() {}`, []string{"testmod.authorize"}},
		{"a helper taking a method value", `package main
import "crypto/hmac"
type T struct{ key []byte }
func (t T) Key() []byte { return t.key }
func h(t T, mac []byte) bool { k := t.Key; return hmac.Equal(k(), mac) }
func F(t T, mac []byte) bool { return h(t, mac) }
func main() {}`, []string{"testmod.h", "crypto/hmac.Equal"}},
		{"a verification result stored in a global", `package main
var last bool
func authorize(u string) bool { return u == "admin" }
func F(u string) { last = authorize(u) }
func main() {}`, nil},
		{"a verification result in a named result changed in a loop", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string, n int) (ok bool) { defer println(); ok = authorize(u); for i := 0; i < n; i++ { ok = !ok }; return }
func main() {}`, []string{"testmod.authorize"}},
		{"a verification result four locals from a branch", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string) int {
	a := authorize(u); println(&a)
	b := a; println(&b)
	c := b; println(&c)
	d := c; println(&d)
	if d { return 1 }
	return 0
}
func main() {}`, []string{"testmod.authorize"}},
		{"a verification result five locals from a branch", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string) int {
	a := authorize(u); println(&a)
	b := a; println(&b)
	c := b; println(&c)
	d := c; println(&d)
	e := d; println(&e)
	if e { return 1 }
	return 0
}
func main() {}`, nil},
		{"a primitive whose result is unused", `package main
import "crypto/hmac"
func F(a, b []byte) { ok := hmac.Equal(a, b); println(ok) }
func main() {}`, nil},
		{"a primitive whose result is dropped", `package main
import "crypto/hmac"
func F(a, b []byte) { hmac.Equal(a, b) }
func main() {}`, nil},
		{"a primitive's int result returned", `package main
import "crypto/subtle"
func F(a, b []byte) int { return subtle.ConstantTimeCompare(a, b) }
func main() {}`, []string{"crypto/subtle.ConstantTimeCompare"}},
		{"a helper returning a primitive's int result", `package main
import "crypto/subtle"
func same(a, b []byte) int { return subtle.ConstantTimeCompare(a, b) }
func F(a, b []byte) bool { return same(a, b) == 1 }
func main() {}`, []string{"testmod.same", "crypto/subtle.ConstantTimeCompare"}},
		{"a helper that ignores its primitive", `package main
import "crypto/hmac"
func macOK(a, b []byte) bool { hmac.Equal(a, b); return true }
func F(a, b []byte) int { if !macOK(a, b) { return 0 }; return 1 }
func main() {}`, nil},
		{"constant-time copy and select compare nothing", `package main
import "crypto/subtle"
func F(dst, src []byte, v int) int { subtle.ConstantTimeCopy(v, dst, src); return subtle.ConstantTimeSelect(v, 1, 2) }
func main() {}`, nil},
		{"a method declared on an alias", `package main
type Server struct{}
type S = Server
func (s *S) authorize(u string) bool { return u == "admin" }
func F(s *Server, u string) int { if !s.authorize(u) { return 0 }; return 1 }
func main() {}`, []string{"(testmod.Server).authorize"}},
		{"a value method declared on an alias", `package main
type Server struct{}
type S = Server
func (s S) authorize(u string) bool { return u == "admin" }
func F(s Server, u string) int { if !s.authorize(u) { return 0 }; return 1 }
func main() {}`, []string{"(testmod.Server).authorize"}},
		{"checks a validate helper makes", `package main
import "errors"
func validName(s string) bool { return s != "" }
func validateHeaders(h map[string]string) string { for k := range h { if !validName(k) { return k } }; return "" }
func F(h map[string]string) error { if bad := validateHeaders(h); bad != "" { return errors.New(bad) }; return nil }
func main() {}`, []string{"testmod.validateHeaders", "testmod.validName"}},
		{"checks another helper makes stay its own", `package main
func validName(s string) bool { return s != "" }
func render(s string) string { if !validName(s) { return "" }; return s }
func F(s string) string { return render(s) }
func main() {}`, nil},
		{"getters returned are no checks", `package main
type Commit struct{ author, token, role string }
func (c *Commit) Author() string { return c.author }
func (c *Commit) AccessToken() string { return c.token }
func (c *Commit) RoleName() string { return c.role }
func F(c *Commit) (string, string, string) { return c.Author(), c.AccessToken(), c.RoleName() }
func main() {}`, nil},
		{"error classifiers are no checks", `package main
import ("os";"reflect")
func F(err error, v reflect.Value) int { if os.IsPermission(err) || !v.IsValid() { return 0 }; return 1 }
func main() {}`, nil},
		{"verification name with the result unused", `package main
func authorize(u string) bool { return u == "admin" }
func F(u string) { authorize(u) }
func main() {}`, nil},
		{"other names deciding a branch", `package main
func checkCache(k string) bool { return len(k) > 3 }
func F(k string) int { if checkCache(k) { return 1 }; return 0 }
func main() {}`, nil},
		{"interface verifier", `package main
type Verifier interface{ Verify(msg []byte) error }
func F(v Verifier, m []byte) int { if v.Verify(m) != nil { return 0 }; return 1 }
func main() {}`, []string{"(testmod.Verifier).Verify"}},
		{"interface verifier with the result unused", `package main
type Verifier interface{ Verify(msg []byte) error }
func F(v Verifier, m []byte) { v.Verify(m) }
func main() {}`, nil},
		{"interface method with another name", `package main
type Store interface{ Load(k string) error }
func F(s Store, k string) int { if s.Load(k) != nil { return 0 }; return 1 }
func main() {}`, nil},
		{"a helper's string result passes its primitives", `package main
import "crypto/hmac"
func render(a, b []byte) string { if !hmac.Equal(a, b) { return "" }; return "ok" }
func F(a, b []byte) string { return render(a, b) }
func main() {}`, []string{"testmod.render", "crypto/hmac.Equal"}},
	}
	srcs := make([]string, len(cases))
	for i, c := range cases {
		srcs[i] = c.src
	}
	tps := topologies(t, srcs...)
	for i, c := range cases {
		tp := tps[i]
		t.Run(c.name, func(t *testing.T) {
			want := map[string]bool{}
			for _, k := range c.want {
				want[k] = true
			}
			if !reflect.DeepEqual(tp.Checks, want) {
				t.Errorf("Checks = %v; want %v", tp.Checks, c.want)
			}
		})
	}
}

func TestHelperMovedChecks(t *testing.T) {
	const ve = "package main\ntype ValidationError struct{ msg string }\nfunc (e *ValidationError) Error() string { return e.msg }\nfunc validName(s string) bool { return s != \"\" }\nfunc process(s string) *ValidationError { if !validName(s) { return &ValidationError{\"bad\"} }; return nil }\n"
	moved := func(k string, vias ...string) map[string][]string { return map[string][]string{k: vias} }
	cases := []struct {
		name, src string
		want      map[string][]string
	}{
		{"a helper whose error decides", `package main
import "errors"
func validName(s string) bool { return s != "" }
func process(s string) error { if !validName(s) { return errors.New("bad") }; return nil }
func F(s string) error { if err := process(s); err != nil { return err }; return nil }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a helper with an action name", `package main
import "errors"
func validPath(p string) bool { return p != "" }
func validWritePath(p string) error { if !validPath(p) { return errors.New("bad") }; return nil }
func F(p string) error { return validWritePath(p) }
func main() {}`, moved("testmod.validPath", "testmod.validWritePath")},
		{"a helper whose bool and error decide", `package main
import "errors"
type Alert struct{}
func verifyCert(c []byte) bool { return len(c) > 0 }
func process(c []byte) (bool, *Alert, error) { if !verifyCert(c) { return false, &Alert{}, errors.New("bad") }; return true, nil, nil }
func F(c []byte) (*Alert, error) { ready, a, err := process(c); if !ready || err != nil { return a, err }; return nil, nil }
func main() {}`, moved("testmod.verifyCert", "testmod.process")},
		{"a branch on a helper's other result", `package main
import "errors"
type Alert struct{}
func verifyCert(c []byte) bool { return len(c) > 0 }
func process(c []byte) (bool, *Alert, error) { if !verifyCert(c) { return false, &Alert{}, errors.New("bad") }; return true, nil, nil }
func F(c []byte) *Alert { _, a, _ := process(c); if a != nil { return a }; return nil }
func main() {}`, nil},
		{"a helper whose result is unused", `package main
import "errors"
func validName(s string) bool { return s != "" }
func process(s string) error { if !validName(s) { return errors.New("bad") }; return nil }
func F(s string) { process(s) }
func main() {}`, nil},
		{"a helper with no result and another name", `package main
func validName(s string) bool { return s != "" }
func record(s string) { if !validName(s) { println("bad") } }
func F(s string) { record(s) }
func main() {}`, nil},
		{"a check-named helper with no result", `package main
func validName(s string) bool { return s != "" }
func mustValidate(s string) { if !validName(s) { panic("bad") } }
func F(s string) { mustValidate(s) }
func main() {}`, moved("testmod.validName", "testmod.mustValidate")},
		{"a name-based check's helpers stay in Checks", `package main
import "errors"
func validName(s string) bool { return s != "" }
func process(s string) error { if !validName(s) { return errors.New("bad") }; return nil }
func validateAll(s string) error { if err := process(s); err != nil { return err }; return nil }
func F(s string) error { return validateAll(s) }
func main() {}`, nil},
		{"through two deciding helpers", `package main
import "errors"
func validName(s string) bool { return s != "" }
func check(s string) error { if !validName(s) { return errors.New("bad") }; return nil }
func process(s string) error { if err := check(s); err != nil { return err }; return nil }
func F(s string) error { if err := process(s); err != nil { return err }; return nil }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"behind a string result", `package main
import "errors"
func validName(s string) bool { return s != "" }
func render(s string) string { if !validName(s) { return "" }; return s }
func process(s string) error { if render(s) == "" { return errors.New("bad") }; return nil }
func F(s string) error { if err := process(s); err != nil { return err }; return nil }
func main() {}`, nil},
		{"three helpers deep", `package main
func validName(s string) bool { return s != "" }
func h3(s string) bool { return validName(s) }
func h2(s string) bool { return h3(s) }
func h1(s string) bool { return h2(s) }
func F(s string) bool { return h1(s) }
func main() {}`, moved("testmod.validName", "testmod.h1")},
		{"four helpers deep is too far", `package main
func validName(s string) bool { return s != "" }
func h4(s string) bool { return validName(s) }
func h3(s string) bool { return h4(s) }
func h2(s string) bool { return h3(s) }
func h1(s string) bool { return h2(s) }
func F(s string) bool { return h1(s) }
func main() {}`, nil},
		{"mutually recursive helpers", `package main
func validName(s string) bool { return s != "" }
func a(s string, n int) bool { if n > 0 { return b(s, n-1) }; return validName(s) }
func b(s string, n int) bool { return a(s, n) }
func F(s string) bool { return a(s, 3) }
func main() {}`, moved("testmod.validName", "testmod.a")},
		{"two helpers reaching a check, sorted", `package main
func validName(s string) bool { return s != "" }
func zeta(s string) bool { return validName(s) }
func alpha(s string) bool { return validName(s) }
func F(s string) bool { return zeta(s) && alpha(s) }
func main() {}`, moved("testmod.validName", "testmod.alpha", "testmod.zeta")},
		{"a validate helper behind a deciding helper", `package main
import "errors"
func validName(s string) bool { return s != "" }
func validateHeaders(h []string) string { for _, k := range h { if !validName(k) { return k } }; return "" }
func process(h []string) error { if bad := validateHeaders(h); bad != "" { return errors.New(bad) }; return nil }
func F(h []string) error { return process(h) }
func main() {}`, map[string][]string{"testmod.validateHeaders": {"testmod.process"}, "testmod.validName": {"testmod.process"}}},
		{"a helper in another package is not followed", `package main
import "testmod/helper"
func F(s string) bool { return helper.Process(s) }
func main() {}`, nil},
		{"a concrete error type", ve + `func F(s string) int { if e := process(s); e != nil { return 0 }; return 1 }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a concrete error result returned", ve + `func F(s string) *ValidationError { return process(s) }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a concrete error result boxed before the branch", ve + `func F(s string) int { var err error = process(s); if err != nil { return 0 }; return 1 }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a concrete error result boxed and returned", ve + `func F(s string) error { return process(s) }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a concrete error result boxed in any and returned", ve + `func F(s string) any { return process(s) }
func main() {}`, nil},
		{"a concrete error result before the last", `package main
type ValidationError struct{ msg string }
func (e *ValidationError) Error() string { return e.msg }
func validName(s string) bool { return s != "" }
func process(s string) (*ValidationError, *ValidationError) { if !validName(s) { return &ValidationError{"bad"}, nil }; return nil, nil }
func F(s string) int { v, _ := process(s); if v != nil { return 0 }; return 1 }
func main() {}`, nil},
		{"a concrete error last of several results", `package main
type ValidationError struct{ msg string }
func (e *ValidationError) Error() string { return e.msg }
func validName(s string) bool { return s != "" }
func process(s string) (int, *ValidationError) { if !validName(s) { return 0, &ValidationError{"bad"} }; return 1, nil }
func F(s string) int { n, e := process(s); if e != nil { return 0 }; return n }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"an instantiated helper returning a concrete error type", `package main
type ValidationError struct{ msg string }
func (e *ValidationError) Error() string { return e.msg }
func validName(s string) bool { return s != "" }
func process[E error](s string, bad E) E { var zero E; if !validName(s) { return bad }; return zero }
func F(s string) int { if e := process(s, &ValidationError{"bad"}); e != nil { return 0 }; return 1 }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a helper returning a type parameter constrained by error", `package main
func validName(s string) bool { return s != "" }
func process[E error](s string, bad E) E { var zero E; if !validName(s) { return bad }; return zero }
func F[E error](s string, bad E) int { var err error = process(s, bad); if err != nil { return 0 }; return 1 }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a helper called in a literal invoked on the spot", ve + `func F(s string) error { return func() error { return process(s) }() }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a helper called in a literal passed to a call", ve + `func retry(f func() error) error { return f() }
func F(s string) error { return retry(func() error { return process(s) }) }
func main() {}`, moved("testmod.validName", "testmod.process")},
		{"a helper called in a stored literal", ve + `var hook func() error
func F(s string) { hook = func() error { return process(s) } }
func main() {}`, nil},
	}
	srcs := make([]string, len(cases))
	for i, c := range cases {
		srcs[i] = c.src
	}
	tps := topologies(t, srcs...)
	for i, c := range cases {
		tp := tps[i]
		t.Run(c.name, func(t *testing.T) {
			if !reflect.DeepEqual(tp.HelperMovedChecks, c.want) {
				t.Errorf("HelperMovedChecks = %v; want %v", tp.HelperMovedChecks, c.want)
			}
		})
	}
}

func TestLiteralChecks(t *testing.T) {
	const hdr = `package main
import "errors"
var errBad = errors.New("bad")
func validate(u string) error { if u == "" { return errBad }; return nil }
type group struct{}
func (*group) Do(k string, f func() (any, error)) (any, error, bool) { v, e := f(); return v, e, false }
type doer interface { Do(string, func() (any, error)) (any, error, bool) }
type resolver func() error
func run(r resolver) error { return r() }
func runAny(f any) error { return nil }
func retry(f func() error) error { return f() }
func try(f func() error) bool { return f() == nil }
var g group
var d doer = &g
var callFn = retry
var keep func() (any, error)
func main() {}
`
	const do = "(testmod.group).Do"
	cases := []struct {
		name, body string
		checks     []string
		moved      map[string]string
	}{
		{"passed to a call whose error decides",
			`_, err, _ := g.Do("k", func() (any, error) { return nil, validate(u) }); return err`,
			nil, map[string]string{"testmod.validate": do}},
		{"capturing nothing",
			`_, err, _ := g.Do("k", func() (any, error) { return nil, validate("") }); return err`,
			nil, map[string]string{"testmod.validate": do}},
		{"passed as a named func type",
			`return run(func() error { return validate(u) })`,
			nil, map[string]string{"testmod.validate": "testmod.run"}},
		{"passed to an interface method",
			`_, err, _ := d.Do("k", func() (any, error) { return nil, validate(u) }); return err`,
			nil, map[string]string{"testmod.validate": "(testmod.doer).Do"}},
		{"passed to a func value",
			`return callFn(func() error { return validate(u) })`,
			nil, map[string]string{"testmod.validate": "func value"}},
		{"nested", `return retry(func() error {
	_, err, _ := g.Do("k", func() (any, error) { return nil, validate(u) }); return err })`,
			nil, map[string]string{"testmod.validate": do}},
		{"invoked on the spot",
			`return func() error { return validate(u) }()`,
			[]string{"testmod.validate"}, nil},
		{"invoked on the spot with no result",
			`func() { if validate(u) != nil { panic(1) } }(); return nil`,
			[]string{"testmod.validate"}, nil},
		{"invoked on the spot, result ignored",
			`func() error { return validate(u) }(); return nil`,
			nil, nil},
		{"only the shared flag decides",
			`_, _, shared := g.Do("k", func() (any, error) { return nil, validate(u) }); if shared { return errBad }; return nil`,
			nil, nil},
		{"a call returning bool",
			`if try(func() error { return validate(u) }) { return nil }; return errBad`,
			nil, nil},
		{"error result unused",
			`_, err, _ := g.Do("k", func() (any, error) { return nil, validate(u) }); _ = err; return nil`,
			nil, nil},
		{"single error result ignored",
			`run(func() error { return validate(u) }); return nil`,
			nil, nil},
		{"call result discarded",
			`g.Do("k", func() (any, error) { return nil, validate(u) }); return nil`,
			nil, nil},
		{"stored as well as passed",
			`f := func() (any, error) { return nil, validate(u) }; _, err, _ := g.Do("k", f); keep = f; return err`,
			nil, nil},
		{"passed as any",
			`return runAny(func() error { return validate(u) })`,
			nil, nil},
		{"deferred and run as a goroutine",
			`defer func() { if validate(u) != nil { panic(1) } }(); go func() { _ = validate(u) }(); return nil`,
			nil, nil},
		{"check ignored inside",
			`_, err, _ := g.Do("k", func() (any, error) { _ = validate(u); return nil, nil }); return err`,
			nil, nil},
	}
	srcs := make([]string, len(cases))
	for i, c := range cases {
		srcs[i] = hdr + "func F(u string) error { " + c.body + " }\n"
	}
	tps := topologies(t, srcs...)
	for i, c := range cases {
		tp := tps[i]
		t.Run(c.name, func(t *testing.T) {
			want := map[string]bool{}
			for _, k := range c.checks {
				want[k] = true
			}
			if !reflect.DeepEqual(tp.Checks, want) {
				t.Errorf("Checks = %v; want %v", tp.Checks, c.checks)
			}
			if len(tp.MovedChecks) != len(c.moved) || len(c.moved) > 0 && !reflect.DeepEqual(tp.MovedChecks, c.moved) {
				t.Errorf("MovedChecks = %v; want %v", tp.MovedChecks, c.moved)
			}
		})
	}
}

func TestSecuritySettings(t *testing.T) {
	cases := []struct {
		name, src    string
		weak, secure []string
	}{
		{"InsecureSkipVerify true", `package main
import "crypto/tls"
func F() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
func main() {}`, []string{"crypto/tls.Config.InsecureSkipVerify=true"}, nil},
		{"InsecureSkipVerify false", `package main
import "crypto/tls"
func F() *tls.Config { return &tls.Config{InsecureSkipVerify: false} }
func main() {}`, nil, nil},
		{"MinVersion and MaxVersion below TLS 1.2", `package main
import "crypto/tls"
func F() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11} }
func main() {}`, []string{"crypto/tls.Config.MaxVersion=TLS1.1", "crypto/tls.Config.MinVersion=TLS1.0"}, nil},
		{"SSL 3.0 and an unnamed old version", `package main
import "crypto/tls"
func F() (*tls.Config, *tls.Config) { return &tls.Config{MinVersion: 0x0300}, &tls.Config{MinVersion: 0x0299} }
func main() {}`, []string{"crypto/tls.Config.MinVersion=665", "crypto/tls.Config.MinVersion=SSL3.0"}, nil},
		{"TLS 1.2 and 1.3", `package main
import "crypto/tls"
func F() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13} }
func main() {}`, nil, nil},
		{"client certificates required and verified", `package main
import "crypto/tls"
func F() *tls.Config { return &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert} }
func main() {}`, nil, []string{"crypto/tls.Config.ClientAuth=RequireAndVerifyClientCert"}},
		{"client certificates requested only", `package main
import "crypto/tls"
func F() *tls.Config { return &tls.Config{ClientAuth: tls.RequireAnyClientCert} }
func main() {}`, nil, nil},
		{"secure cookie", `package main
import "net/http"
func F() *http.Cookie { return &http.Cookie{Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode} }
func main() {}`, nil, []string{"net/http.Cookie.HttpOnly=true", "net/http.Cookie.Secure=true"}},
		{"cookie with SameSite=None", `package main
import "net/http"
func F() *http.Cookie { return &http.Cookie{Secure: false, SameSite: http.SameSiteNoneMode} }
func main() {}`, []string{"net/http.Cookie.SameSite=SameSiteNoneMode"}, nil},
		{"non-constant value", `package main
import "crypto/tls"
func F(skip bool) *tls.Config { return &tls.Config{InsecureSkipVerify: skip} }
func main() {}`, nil, nil},
		{"same field name on another struct", `package main
type Config struct{ InsecureSkipVerify bool; Secure bool }
func F() *Config { return &Config{InsecureSkipVerify: true, Secure: true} }
func main() {}`, nil, nil},
		{"assignment after construction", `package main
import "crypto/tls"
func F() *tls.Config { c := &tls.Config{}; c.InsecureSkipVerify = true; return c }
func main() {}`, []string{"crypto/tls.Config.InsecureSkipVerify=true"}, nil},
		{"constant stores that are not to a field", `package main
var g bool
func F(p *int) { g = true; *p = 1 }
func main() {}`, nil, nil},
		{"store to an unnamed struct", `package main
func F() any { p := &struct{ InsecureSkipVerify bool }{}; p.InsecureSkipVerify = true; return p }
func main() {}`, nil, nil},
		{"ssh host key checking disabled", `package main
import "golang.org/x/crypto/ssh"
func F() ssh.HostKeyCallback { return ssh.InsecureIgnoreHostKey() }
func main() {}`, []string{"golang.org/x/crypto/ssh.InsecureIgnoreHostKey()"}, nil},
		{"ssh host key pinned", `package main
import "golang.org/x/crypto/ssh"
func F() ssh.HostKeyCallback { return ssh.FixedHostKey() }
func main() {}`, nil, nil},
		{"method of the same name", `package main
import "golang.org/x/crypto/ssh"
func F(c ssh.Config) ssh.HostKeyCallback { return c.InsecureIgnoreHostKey() }
func main() {}`, nil, nil},
		{"function of the same name in another package", `package main
import "testmod/fake/ssh"
func F() ssh.HostKeyCallback { return ssh.InsecureIgnoreHostKey() }
func main() {}`, nil, nil},
		{"ssh host key checking disabled through a function value", `package main
import "golang.org/x/crypto/ssh"
func F() ssh.HostKeyCallback { cbs := []func() ssh.HostKeyCallback{ssh.InsecureIgnoreHostKey}; return cbs[0]() }
func main() {}`, []string{"golang.org/x/crypto/ssh.InsecureIgnoreHostKey()"}, nil},
		{"a defined type over tls.Config", `package main
import "crypto/tls"
type cfg tls.Config
func F() *tls.Config { return (*tls.Config)(&cfg{InsecureSkipVerify: true, ClientAuth: tls.RequireAndVerifyClientCert}) }
func main() {}`, []string{"crypto/tls.Config.InsecureSkipVerify=true"}, []string{"crypto/tls.Config.ClientAuth=RequireAndVerifyClientCert"}},
		{"a defined type over http.Cookie", `package main
import "net/http"
type cookie http.Cookie
func F() *http.Cookie { return (*http.Cookie)(&cookie{Secure: true, SameSite: http.SameSiteNoneMode}) }
func main() {}`, []string{"net/http.Cookie.SameSite=SameSiteNoneMode"}, []string{"net/http.Cookie.Secure=true"}},
		{"a struct embedding tls.Config", `package main
import "crypto/tls"
type wrapped struct{ tls.Config }
func F() *wrapped { w := &wrapped{}; w.InsecureSkipVerify = true; return w }
func main() {}`, []string{"crypto/tls.Config.InsecureSkipVerify=true"}, nil},
		{"MinVersion reset to the default", `package main
import "crypto/tls"
func F(c *tls.Config) { c.MinVersion = 0 }
func main() {}`, nil, nil},
		{"Secure set, then cleared", `package main
import "net/http"
func F() *http.Cookie { c := &http.Cookie{Secure: true, HttpOnly: true}; c.Secure = false; return c }
func main() {}`, nil, []string{"net/http.Cookie.HttpOnly=true"}},
		{"ClientAuth set, then lowered", `package main
import "crypto/tls"
func F() *tls.Config { c := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}; c.ClientAuth = tls.NoClientCert; return c }
func main() {}`, nil, nil},
		{"a second cookie without the settings", `package main
import "net/http"
func F(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "pref", Value: "1", Secure: true, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "session", Value: v})
}
func main() {}`, nil, nil},
		{"two cookies with the settings", `package main
import "net/http"
func F(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "pref", Value: "1", Secure: true})
	http.SetCookie(w, &http.Cookie{Name: "session", Value: v, Secure: true})
}
func main() {}`, nil, []string{"net/http.Cookie.Secure=true"}},
		{"settings on a cookie passed in", `package main
import "net/http"
func F(c *http.Cookie) { c.Secure = true }
func main() {}`, nil, []string{"net/http.Cookie.Secure=true"}},
		{"a helper returning a secure cookie", `package main
import "net/http"
func session(v string) *http.Cookie { return &http.Cookie{Name: "s", Value: v, Secure: true, HttpOnly: true} }
func F(w http.ResponseWriter, v string) { http.SetCookie(w, session(v)) }
func main() {}`, nil, []string{"net/http.Cookie.HttpOnly=true", "net/http.Cookie.Secure=true"}},
		{"a helper that secures the caller's cookie", `package main
import "net/http"
func harden(c *http.Cookie) { c.Secure = true }
func F(w http.ResponseWriter, v string) { c := &http.Cookie{Name: "s", Value: v}; harden(c); http.SetCookie(w, c) }
func main() {}`, nil, []string{"net/http.Cookie.Secure=true"}},
		{"a helper's cookie beside one without the setting", `package main
import "net/http"
func session(v string) *http.Cookie { return &http.Cookie{Name: "s", Value: v, Secure: true} }
func F(w http.ResponseWriter, v string) { http.SetCookie(w, session(v)); http.SetCookie(w, &http.Cookie{Name: "t", Value: v}) }
func main() {}`, nil, nil},
		{"a helper three calls deep", `package main
import "net/http"
func h3(v string) *http.Cookie { return &http.Cookie{Name: "s", Value: v, Secure: true} }
func h2(v string) *http.Cookie { return h3(v) }
func h1(v string) *http.Cookie { return h2(v) }
func F(v string) *http.Cookie { return h1(v) }
func main() {}`, nil, []string{"net/http.Cookie.Secure=true"}},
		{"a helper four calls deep is too far", `package main
import "net/http"
func h4(v string) *http.Cookie { return &http.Cookie{Name: "s", Value: v, Secure: true} }
func h3(v string) *http.Cookie { return h4(v) }
func h2(v string) *http.Cookie { return h3(v) }
func h1(v string) *http.Cookie { return h2(v) }
func F(v string) *http.Cookie { return h1(v) }
func main() {}`, nil, nil},
		{"a function value's cookie is not followed", `package main
import "net/http"
func F(mk func() *http.Cookie) *http.Cookie { return mk() }
func main() {}`, nil, nil},
		{"a closure's cookie belongs to the closure", `package main
import "net/http"
func F() *http.Cookie { mk := func() *http.Cookie { return &http.Cookie{Secure: true} }; return mk() }
func main() {}`, nil, nil},
		{"a helper in another package is not followed", `package main
import ("net/http";"testmod/helper")
func F(v string) *http.Cookie { return helper.Cookie(v) }
func main() {}`, nil, nil},
	}
	srcs := make([]string, len(cases))
	for i, c := range cases {
		srcs[i] = c.src
	}
	tps := topologies(t, srcs...)
	for i, c := range cases {
		tp := tps[i]
		t.Run(c.name, func(t *testing.T) {
			set := func(names []string) map[string]bool {
				if names == nil {
					return nil
				}
				m := make(map[string]bool)
				for _, n := range names {
					m[n] = true
				}
				return m
			}
			if !reflect.DeepEqual(tp.WeakSettings, set(c.weak)) || !reflect.DeepEqual(tp.SecureSettings, set(c.secure)) {
				t.Errorf("weak %v, secure %v; want %v, %v", tp.WeakSettings, tp.SecureSettings, c.weak, c.secure)
			}
		})
	}
}

func TestCallTargets(t *testing.T) {
	cases := []struct {
		name, src    string
		targets      map[string]int
		capabilities map[string]string
	}{
		{"each call counts", `package main
import "os"
func F(p string) { os.Remove(p); os.Remove(p + "~") }
func main() {}`, map[string]int{"os.Remove": 2}, map[string]string{"os.Remove": "filesystem"}},
		{"a method named init", `package main
type T struct{}
func (T) init() {}
func F(t T) { t.init() }
func main() {}`, map[string]int{"(testmod.T).init": 1}, map[string]string{}},
		{"error.Error as a method value", `package main
func F(err error) func() string { return err.Error }
func main() {}`, map[string]int{"(.error).Error": 1}, map[string]string{}},
		{"a closure is not a target", `package main
func F() int { f := func() int { return 1 }; return f() }
func main() {}`, map[string]int{}, map[string]string{}},
		{"exec.Cmd run through an interface", `package main
import "os/exec"
type runner interface{ Run() error }
func F(x string) error { var r runner = &exec.Cmd{Path: "/bin/sh", Args: []string{"sh", "-c", x}}; return r.Run() }
func main() {}`, map[string]int{"(os/exec.Cmd).Run": 1}, map[string]string{"(os/exec.Cmd).Run": "exec"}},
		{"an error conversion adds nothing", `package main
type E struct{}
func (*E) Error() string { return "e" }
func F() error { return &E{} }
func main() {}`, map[string]int{}, map[string]string{}},
		{"exec.Cmd passed for a constrained type parameter", `package main
import "os/exec"
func run[T interface{ Run() error }](c T) error { return c.Run() }
func F(x string) error { return run(&exec.Cmd{Path: x}) }
func main() {}`, map[string]int{"testmod.run": 1, "(os/exec.Cmd).Run": 1}, map[string]string{"(os/exec.Cmd).Run": "exec"}},
		{"a request sent through http.RoundTripper", `package main
import "net/http"
func F(req *http.Request) (*http.Response, error) { return http.DefaultTransport.RoundTrip(req) }
func main() {}`, map[string]int{"(net/http.RoundTripper).RoundTrip": 1}, map[string]string{"(net/http.RoundTripper).RoundTrip": "network"}},
		{"http.DefaultClient through an interface", `package main
import "net/http"
type doer interface{ Do(*http.Request) (*http.Response, error) }
func F(req *http.Request) (*http.Response, error) { var d doer = http.DefaultClient; return d.Do(req) }
func main() {}`, map[string]int{"(net/http.Client).Do": 1}, map[string]string{"(net/http.Client).Do": "network"}},
		{"calls through an unnamed interface and through error", `package main
func F(r interface{ RoundTrip() }, err error) string { r.RoundTrip(); return err.Error() }
func main() {}`, map[string]int{}, map[string]string{}},
		{"an interface passed for a type parameter", `package main
import "net/http"
func run[T interface{ RoundTrip(*http.Request) (*http.Response, error) }](t T, r *http.Request) { t.RoundTrip(r) }
func F(r *http.Request) { run[http.RoundTripper](http.DefaultTransport, r) }
func main() {}`, map[string]int{"testmod.run": 1}, map[string]string{}},
		{"another interface's method of the same name", `package main
type RoundTripper interface{ RoundTrip(int) int }
func F(r RoundTripper) int { return r.RoundTrip(1) }
func main() {}`, map[string]int{}, map[string]string{}},
	}
	srcs := make([]string, len(cases))
	for i, c := range cases {
		srcs[i] = c.src
	}
	fns := functions(t, srcs...)
	for i, c := range cases {
		fn := fns[i]
		t.Run(c.name, func(t *testing.T) {
			tp := topology.ExtractTopology(fn)
			pkgPath := fn.Pkg.Pkg.Path()
			targets, capabilities := rekey(tp.CallTargets, pkgPath), rekey(tp.Capabilities, pkgPath)
			if !reflect.DeepEqual(targets, c.targets) || !reflect.DeepEqual(capabilities, c.capabilities) {
				t.Errorf("CallTargets = %v, Capabilities = %v; want %v, %v", targets, capabilities, c.targets, c.capabilities)
			}
		})
	}
}

func TestErrorExits(t *testing.T) {
	cases := []struct {
		name, src string
		want      int
	}{
		{"error check returning err", `package main
import "os"
func F(p string) error { if _, err := os.Stat(p); err != nil { return err }; return nil }
func main() {}`, 1},
		{"nil check written the other way", `package main
import "os"
func F(p string) error { _, err := os.Stat(p); if err == nil { return nil }; return err }
func main() {}`, 1},
		{"errors.New", `package main
import "errors"
func F(ok bool) error { if !ok { return errors.New("no") }; return nil }
func main() {}`, 1},
		{"fmt.Errorf", `package main
import "fmt"
func F(n int) error { if n < 0 { return fmt.Errorf("bad %d", n) }; return nil }
func main() {}`, 1},
		{"errors.Join", `package main
import "errors"
func F(a, b error) error { if a != nil { return errors.Join(a, b) }; return nil }
func main() {}`, 1},
		{"sentinel error", `package main
import "errors"
var ErrNo = errors.New("no")
func F(ok bool) error { if !ok { return ErrNo }; return nil }
func main() {}`, 1},
		{"concrete error type", `package main
type E struct{}
func (*E) Error() string { return "e" }
func F(ok bool) error { if !ok { return &E{} }; return nil }
func main() {}`, 1},
		{"panic", `package main
func F(ok bool) int { if !ok { panic("no") }; return 1 }
func main() {}`, 1},
		{"log.Fatal", `package main
import "log"
func F(ok bool) int { if !ok { log.Fatal("no") }; return 1 }
func main() {}`, 1},
		{"http.Error", `package main
import "net/http"
func F(w http.ResponseWriter, ok bool) { if !ok { http.Error(w, "no", 403); return }; w.Write(nil) }
func main() {}`, 1},
		{"http.NotFound", `package main
import "net/http"
func F(w http.ResponseWriter, r *http.Request, ok bool) { if !ok { http.NotFound(w, r); return }; w.Write(nil) }
func main() {}`, 1},
		{"WriteHeader 4xx", `package main
import "net/http"
func F(w http.ResponseWriter, ok bool) { if !ok { w.WriteHeader(401); return }; w.Write(nil) }
func main() {}`, 1},
		{"WriteHeader 2xx is not a failure", `package main
import "net/http"
func F(w http.ResponseWriter, ok bool) { if !ok { w.WriteHeader(204); return }; w.Write(nil) }
func main() {}`, 0},
		{"a passed-through result is not a failure", `package main
import "os"
func F(p string, ok bool) error { if ok { return os.Remove(p) }; return os.RemoveAll(p) }
func main() {}`, 0},
		{"failure on both sides is not a check", `package main
import "errors"
func F(ok bool) error { if ok { return errors.New("a") }; return errors.New("b") }
func main() {}`, 0},
		{"no error result", `package main
func F(n int) int { if n > 1 { return 2 }; return 1 }
func main() {}`, 0},
		{"nil compared on the left", `package main
import "os"
func F(p string) error { if _, err := os.Stat(p); nil != err { return err }; return nil }
func main() {}`, 1},
		{"error returned under a boolean condition", `package main
import "os"
func F(p string, ok bool) error { err := os.Remove(p); if ok { return err }; return nil }
func main() {}`, 0},
		{"error returned under an ordering", `package main
import "os"
func F(p string, n int) error { err := os.Remove(p); if n > 0 { return err }; return nil }
func main() {}`, 0},
		{"another error than the one tested", `package main
import "os"
func F(a, b string) error {
	_, errA := os.Stat(a)
	_, errB := os.Stat(b)
	if errB != nil { return errA }
	return nil
}
func main() {}`, 0},
		{"error compared with another error", `package main
import ("io";"os")
func F(f *os.File, b []byte) error { _, err := f.Read(b); if err != io.EOF { return err }; return nil }
func main() {}`, 0},
		{"WriteHeader 400", `package main
import "net/http"
func F(w http.ResponseWriter, ok bool) { if !ok { w.WriteHeader(400); return }; w.Write(nil) }
func main() {}`, 1},
		{"WriteHeader with a variable status", `package main
import "net/http"
func F(w http.ResponseWriter, code int, ok bool) { if !ok { w.WriteHeader(code); return }; w.Write(nil) }
func main() {}`, 0},
		{"WriteHeader of another interface, with a string", `package main
type W interface{ WriteHeader(s string) }
func F(w W, ok bool) { if !ok { w.WriteHeader("x"); return }; w.WriteHeader("y") }
func main() {}`, 0},
		{"a redirect is not an error response", `package main
import "net/http"
func F(w http.ResponseWriter, r *http.Request, ok bool) { if !ok { http.Redirect(w, r, "/", 302); return }; w.Write(nil) }
func main() {}`, 0},
		{"errors.Unwrap is not a new error", `package main
import "errors"
func F(err error, ok bool) error { if !ok { return errors.Unwrap(err) }; return nil }
func main() {}`, 0},
		{"a local New is not errors.New", `package main
func New(s string) error { return nil }
func F(ok bool) error { if !ok { return New("no") }; return nil }
func main() {}`, 0},
		{"a local Errorf is not fmt.Errorf", `package main
func Errorf(s string) error { return nil }
func F(ok bool) error { if !ok { return Errorf("no") }; return nil }
func main() {}`, 0},
		{"an error method named New is not errors.New", `package main
type B struct{}
func (B) New(s string) error { return nil }
func F(b B, ok bool) error { if !ok { return b.New("no") }; return nil }
func main() {}`, 0},
		{"a net/http method named Error", `package main
import "net/http"
func F(w http.ResponseWriter, e *http.MaxBytesError, ok bool) { if !ok { _ = e.Error(); return }; w.Write(nil) }
func main() {}`, 0},
		{"a side that branches again is not followed", `package main
import "errors"
func F(ok, z bool) error {
	if ok { return nil }
	if z { return errors.New("z") }
	return nil
}
func main() {}`, 1},
		{"a side that jumps to a shared failure block", `package main
func F(a, b bool) int {
	if a { println("a"); goto fail }
	if b { println("b"); goto fail }
	return 1
fail:
	panic("no")
}
func main() {}`, 2},
		{"an error kept in a field is passed through", `package main
type S struct{ err error }
func F(s *S, ok bool) error { if !ok { return s.err }; return nil }
func main() {}`, 0},
		{"an error from a function value is passed through", `package main
func F(f func() error, ok bool) error { if !ok { return f() }; return nil }
func main() {}`, 0},
		{"WriteHeader of a nil constant", `package main
type Header map[string]string
type W interface{ WriteHeader(h Header) }
func F(w W, ok bool) { if !ok { w.WriteHeader(nil); return }; w.WriteHeader(Header{"a": "b"}) }
func main() {}`, 0},
		{"WriteHeader of an empty struct", `package main
type Status struct{ Code int }
type W interface{ WriteHeader(s Status) }
func F(w W, ok bool) { if !ok { w.WriteHeader(Status{}); return }; w.WriteHeader(Status{1}) }
func main() {}`, 0},
		{"WriteHeader with no argument", `package main
type W interface{ WriteHeader() }
func F(w W, ok bool) { if !ok { w.WriteHeader(); return }; println() }
func main() {}`, 0},
		{"a pointer result is not an error", `package main
type T struct{}
func F(p *T) *T { if p != nil { return p }; return nil }
func main() {}`, 0},
		{"checks in a function with a defer", `package main
import ("errors";"os")
func F(p string) error {
	f, err := os.Open(p)
	if err != nil { return err }
	defer f.Close()
	if p == "" { return errors.New("empty") }
	return nil
}
func main() {}`, 2},
		{"a named result set before a bare return", `package main
import "errors"
func F(p string) (err error) { defer println(); if p == "" { err = errors.New("x"); return }; return nil }
func main() {}`, 1},
		{"a named error result set before another result", `package main
import "errors"
func F(p string) (n int, err error) { defer println(); if p == "" { err = errors.New("empty"); n = -1; return }; return len(p), nil }
func main() {}`, 1},
		{"a constant condition is no check", `package main
import "errors"
func F() error { if false { return errors.New("x") }; return nil }
func main() {}`, 0},
		{"a helper of the package that always exits", `package main
import "os"
func die() { os.Exit(1) }
func F(ok bool) int { if !ok { die() }; return 1 }
func main() {}`, 1},
		{"a side that never ends is no error exit", `package main
func F(ok bool) error { if !ok { for {} }; return nil }
func main() {}`, 0},
		{"two checks", `package main
import ("errors";"os")
func F(p string, ok bool) error {
	if !ok { return errors.New("no") }
	if _, err := os.Stat(p); err != nil { return err }
	return nil
}
func main() {}`, 2},
	}
	srcs := make([]string, len(cases))
	for i, c := range cases {
		srcs[i] = c.src
	}
	tps := topologies(t, srcs...)
	for i, c := range cases {
		tp := tps[i]
		t.Run(c.name, func(t *testing.T) {
			if got := tp.ErrorExits; got != c.want {
				t.Errorf("ErrorExits = %d; want %d", got, c.want)
			}
		})
	}
}

func TestCalleeCapability(t *testing.T) {
	fn := functions(t, `package main
import (
	"fmt"
	"net/http"
	"os"
	"slices"
)
func F(c *http.Client, r *http.Request, p string, s []int) {
	os.Remove(p)
	c.Do(r)
	do := c.Do
	do(r)
	fmt.Println(p, slices.Contains(s, 1))
}
func main() {}`)[0]
	got := map[string]string{}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if call, ok := instr.(*ssa.Call); ok {
				if callee := call.Call.StaticCallee(); callee != nil {
					key, class, ok := topology.CalleeCapability(callee)
					if !ok {
						t.Errorf("CalleeCapability(%s) not ok", callee)
					}
					got[key] = class
				}
			}
		}
	}
	want := map[string]string{
		"os.Remove":            topology.CapFilesystem,
		"(net/http.Client).Do": topology.CapNetwork, // the call and the bound method value
		"fmt.Println":          "",
		"slices.Contains":      "", // an instantiation is keyed by its generic function
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CalleeCapability keys and classes = %v; want %v", got, want)
	}

	inits := 0
	for _, b := range fn.Pkg.Func("init").Blocks {
		for _, instr := range b.Instrs {
			if call, ok := instr.(*ssa.Call); ok {
				if callee := call.Call.StaticCallee(); callee != nil && callee.Name() == "init" {
					inits++
					if key, class, ok := topology.CalleeCapability(callee); ok || key != "" || class != "" {
						t.Errorf("CalleeCapability(%s) = %q, %q, %v; want a package initializer to be no call target", callee, key, class, ok)
					}
				}
			}
		}
	}
	if inits < 4 {
		t.Errorf("found %d imported package initializers; want 4", inits)
	}
}
