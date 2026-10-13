package diff_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/diff"
)

// fingerprintsOf fingerprints every function in src and returns them keyed by
// short function name.
func fingerprintsOf(t *testing.T, src string) map[string]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := diff.FingerprintSource(path, src, ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource: %v", err)
	}
	out := make(map[string]string, len(results))
	for _, r := range results {
		out[diff.ShortFuncName(r.FunctionName)] = r.Fingerprint
	}
	return out
}

// collisionSrc holds pairs of functions whose behaviour differs in a
// security-relevant way. SECURITY.md classes a shared fingerprint for any of
// them as a semantic collision.
const collisionSrc = `package x

import (
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"hash"
	mrand "math/rand"
)

func AuthA(user, pass string) bool {
	if user == "admin" && pass == "hunter2" {
		return true
	}
	return false
}

func AuthB(user, pass string) bool {
	if user == "admin" && pass == "hunter2" {
		return true
	}
	return true
}

func TLSA() *tls.Config { c := &tls.Config{}; c.InsecureSkipVerify = false; return c }
func TLSB() *tls.Config { c := &tls.Config{}; c.InsecureSkipVerify = true; return c }

func KeyA(b []byte) error { _, err := crand.Read(b); return err }
func KeyB(b []byte) error { _, err := mrand.Read(b); return err }

func HashA() hash.Hash { return sha256.New() }
func HashB() hash.Hash { return md5.New() }

type Safe struct{}
type Unsafe struct{}

func (Safe) Run(s string) string   { return s }
func (Unsafe) Run(s string) string { return s + s }

func CallA(s string) string { return Safe{}.Run(s) }
func CallB(s string) string { return Unsafe{}.Run(s) }

func allow() {}
func deny()  { println() }

func SelA(admin, guest chan int) {
	select {
	case <-admin:
		allow()
	case <-guest:
		deny()
	}
}

func SelB(admin, guest chan int) {
	select {
	case <-guest:
		allow()
	case <-admin:
		deny()
	}
}

func useA(x int) {}
func useB(x int) { println(x) }

func RecvA(a, b chan int) {
	select {
	case x := <-a:
		useA(x)
	case y := <-b:
		useB(y)
	}
}

func RecvB(a, b chan int) {
	select {
	case x := <-b:
		useA(x)
	case y := <-a:
		useB(y)
	}
}

func NestA(m [][]byte, n int) {
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			m[i][j] = byte(i)
		}
	}
}

func NestB(m [][]byte, n int) {
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			m[j][i] = byte(j)
		}
	}
}

func WrapA() int {
	n := 0
	for i := int8(1); i > 0; i += 8 {
		n++
	}
	return n
}

func WrapB() int {
	n := 0
	for i := int64(1); i > 0; i += 8 {
		n++
	}
	return n
}

func GeoA(n int, buf []int) {
	for i := 1; i < n; i *= 2 {
		buf[0] = i
	}
}

func GeoB(n int, buf []int) {
	i := 1
	for k := 0; i < n; k++ {
		buf[0] = i
		i = 4*k + 2
	}
}
`

func TestFingerprint_NoSemanticCollisions(t *testing.T) {
	fps := fingerprintsOf(t, collisionSrc)
	pairs := [][2]string{
		{"AuthA", "AuthB"},
		{"TLSA", "TLSB"},
		{"KeyA", "KeyB"},
		{"HashA", "HashB"},
		{"CallA", "CallB"},
		{"SelA", "SelB"},
		{"RecvA", "RecvB"},
		{"NestA", "NestB"},
		{"WrapA", "WrapB"},
		{"GeoA", "GeoB"},
	}
	for _, p := range pairs {
		a, b := fps[p[0]], fps[p[1]]
		if a == "" || b == "" {
			t.Fatalf("missing fingerprint for %s or %s: %v", p[0], p[1], fps)
		}
		if a == b {
			t.Errorf("%s and %s behave differently but share fingerprint %s", p[0], p[1], a[:16])
		}
	}
}

// Renaming locals and parameters must not change the fingerprint; the fixes
// for the collisions above must not cost this invariance.
func TestFingerprint_RenameInvariance(t *testing.T) {
	fps := fingerprintsOf(t, `package x

import "strings"

func A(name string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += strings.ToUpper(name)
	}
	return out
}

func B(s string, count int) string {
	acc := ""
	for k := 0; k < count; k++ {
		acc += strings.ToUpper(s)
	}
	return acc
}
`)
	if fps["A"] != fps["B"] {
		t.Errorf("renamed locals changed the fingerprint: %s vs %s", fps["A"], fps["B"])
	}
}

// Range-over-func loop bodies are synthetic closures; they used to be skipped
// entirely, so anything inside such a loop was invisible.
func TestFingerprint_RangeOverFuncBodies(t *testing.T) {
	fps := fingerprintsOf(t, `package x

import (
	"os"
	"slices"
)

func IterA(s []string) {
	for v := range slices.Values(s) {
		_ = v
	}
}

func IterB(s []string) {
	for v := range slices.Values(s) {
		os.RemoveAll(v)
	}
}
`)
	a, b := fps["IterA$1"], fps["IterB$1"]
	if a == "" || b == "" {
		t.Fatalf("range-over-func bodies not fingerprinted: %v", fps)
	}
	if a == b {
		t.Error("loop bodies differ but share a fingerprint")
	}
}

// Functions too large to canonicalize used to share the constant fingerprint
// "OVERSIZED", so any change inside one was invisible.
func TestFingerprint_OversizedFunctionsStillChange(t *testing.T) {
	big := func(name, tail string) string {
		var b strings.Builder
		fmt.Fprintf(&b, "func %s(x int) int {\n", name)
		for i := 0; i < diff.MaxFunctionBlocks/2+10; i++ {
			fmt.Fprintf(&b, "\tif x == %d {\n\t\treturn %d\n\t}\n", i, i)
		}
		fmt.Fprintf(&b, "\t%s\n\treturn -1\n}\n", tail)
		return b.String()
	}
	fps := fingerprintsOf(t, "package x\n\nimport \"os\"\n\n"+
		big("BigA", "_ = x")+big("BigB", "os.Exit(x)"))
	a, b := fps["BigA"], fps["BigB"]
	if a == "" || b == "" || a == "OVERSIZED" {
		t.Fatalf("unexpected oversized fingerprints: %q %q", a, b)
	}
	if a == b {
		t.Error("oversized functions differ but share a fingerprint")
	}
}
