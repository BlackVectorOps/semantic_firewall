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

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/topology"
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
		"helper/helper.go":   "package helper\n\nimport (\"crypto/hmac\"; \"os\")\n\nfunc Same(a, b []byte) bool { return hmac.Equal(a, b) }\n\nfunc Die() { os.Exit(1) }\n",
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
		{"a closure is a function of its own", `package main
import "crypto/hmac"
func F(a, b []byte) bool { f := func() bool { return hmac.Equal(a, b) }; return f() }
func main() {}`, nil},
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
