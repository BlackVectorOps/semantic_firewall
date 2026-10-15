package diff_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/testutil"
)

func TestRegression_LogicCorruption(t *testing.T) {
	t.Parallel()
	// Ensure GEQ is normalized to LSS with branch swap
	src := `package main
	func cmp(a, b int) bool {
		if a >= b { return true }
		return false
	}`

	// Create an isolated build environment to prevent GOMODCACHE overlay errors
	dir, cleanup := testutil.SetupTestEnv(t, "diff-test-")
	defer cleanup()

	// Use a filename within the isolated directory to satisfy go/packages overlay rules
	path := filepath.Join(dir, "main.go")

	// We use FingerprintSource which invokes the virtual control flow logic in fingerprinter.go
	results, err := diff.FingerprintSource(path, src, ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	// Filter for the specific function we care about.
	// Depending on how SSA builds, we might see 'init' or 'main' as well.
	var target *diff.FingerprintResult
	for i := range results {
		if strings.HasSuffix(results[i].FunctionName, "cmp") {
			target = &results[i]
			break
		}
	}

	if target == nil {
		t.Fatalf("Expected function 'cmp' not found in results. Found: %v", testutil.GetFunctionNames(results))
	}

	out := target.CanonicalIR

	if strings.Contains(out, "BinOp >=") {
		t.Error("GEQ should be normalized to LSS")
	}
	if !strings.Contains(out, "BinOp <") {
		t.Error("Expected BinOp < (LSS) after normalization")
	}
}

func TestRegression_SafeNormalization_Referrers(t *testing.T) {
	t.Parallel()
	// This test ensures that normalization (swapping >= to <) is SKIPPED
	// if the boolean result is used by something other than the If statement.
	// If it were normalized, 'return cond' would return the inverted value.
	src := `package main
	func check(a, b int) bool {
		cond := a >= b
		if cond {
			return true
		}
		return cond
	}`

	dir, cleanup := testutil.SetupTestEnv(t, "diff-ref-")
	defer cleanup()
	path := filepath.Join(dir, "main.go")

	results, err := diff.FingerprintSource(path, src, ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}
	out := results[0].CanonicalIR

	// Expect GEQ to be preserved.
	if !strings.Contains(out, "BinOp >=") {
		t.Error("Unsafe normalization occurred: GEQ replaced despite being used in Return")
	}
}

func TestGetHardenedEnv_Integrity(t *testing.T) {
	// Verify that GetHardenedEnv preserves system variables (like PATH)
	// and appends overrides.
	env := diff.GetHardenedEnv()

	hasPath := false
	hasOverride := false

	for _, e := range env {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "PATH=") || strings.HasPrefix(upper, "Path=") {
			hasPath = true
		}
		if e == "CGO_ENABLED=0" {
			hasOverride = true
		}
	}

	if !hasPath {
		t.Error("GetHardenedEnv truncated the environment: PATH is missing")
	}
	if !hasOverride {
		t.Error("GetHardenedEnv failed to append CGO_ENABLED=0")
	}
}

func TestZipper_StringCommutativity(t *testing.T) {
	t.Parallel()
	// "a" + "b" != "b" + "a"
	// The Zipper should NOT mark these as equivalent.
	// We use parameters to prevent constant folding from obscuring the test.
	src1 := `package main
	func foo(a, b string) string {
		return a + b
	}`
	src2 := `package main
	func foo(a, b string) string {
		return b + a
	}`

	dir, cleanup := testutil.SetupTestEnv(t, "zip-str-")
	defer cleanup()

	// We run fingerprints manually to feed the zipper
	res1, _ := diff.FingerprintSource(filepath.Join(dir, "v1.go"), src1, ir.DefaultLiteralPolicy)
	res2, _ := diff.FingerprintSource(filepath.Join(dir, "v2.go"), src2, ir.DefaultLiteralPolicy)

	z, err := diff.NewZipper(res1[0].GetSSAFunction(), res2[0].GetSSAFunction(), ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("Zipper init failed: %v", err)
	}

	artifacts, err := z.ComputeDiff()
	if err != nil {
		t.Fatalf("ComputeDiff failed: %v", err)
	}

	if artifacts.Preserved {
		t.Error("Zipper incorrectly identified swapped string concatenation as preserved")
	}
}

func TestZipper_IntCommutativity(t *testing.T) {
	t.Parallel()
	// "a" + "b" == "b" + "a" for integers.
	// The Zipper SHOULD mark these as equivalent (Preserved = true).
	// We use parameters to prevent constant folding from obscuring the test.
	src1 := `package main
	func foo(a, b int) int {
		return a + b
	}`
	src2 := `package main
	func foo(a, b int) int {
		return b + a
	}`

	dir, cleanup := testutil.SetupTestEnv(t, "zip-int-")
	defer cleanup()

	// We run fingerprints manually to feed the zipper
	res1, _ := diff.FingerprintSource(filepath.Join(dir, "v1.go"), src1, ir.DefaultLiteralPolicy)
	res2, _ := diff.FingerprintSource(filepath.Join(dir, "v2.go"), src2, ir.DefaultLiteralPolicy)

	z, err := diff.NewZipper(res1[0].GetSSAFunction(), res2[0].GetSSAFunction(), ir.DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("Zipper init failed: %v", err)
	}

	artifacts, err := z.ComputeDiff()
	if err != nil {
		t.Fatalf("ComputeDiff failed: %v", err)
	}

	if !artifacts.Preserved {
		t.Error("Zipper failed to identify swapped integer addition as preserved")
	}
}

// FingerprintPackagesWhere returns what FingerprintPackages returns for the
// files keep accepts and the functions without a file (the package
// initializer), judging each closure by its own file: a //line directive
// places G's closure in a.go.
func TestFingerprintPackagesWhere_MatchesFilteredResults(t *testing.T) {
	root := t.TempDir()
	sources := map[string]string{
		"p/a.go": "package p\n\nfunc F(x int) int {\n\tg := func() int { return x + 1 }\n\treturn g()\n}\n",
		"p/b.go": "package p\n\nvar H = func() int { return 2 }\n\ntype T struct{}\n\nfunc (T) M() int { return 3 }\n\nfunc Asm() int\n\n" +
			"func G() int {\n\tk := 0\n//line a.go:90\n\th := func() int { return k }\n\treturn h()\n}\n",
	}
	overlay := map[string][]byte{}
	for name, src := range sources {
		overlay[filepath.Join(root, filepath.FromSlash(name))] = []byte(src)
	}
	overlay[filepath.Join(root, "go.mod")] = []byte("module example.com/m\n\ngo 1.22\n")
	overlay[filepath.Join(root, "p", "asm.s")] = []byte("// Asm's body.\n")
	for path, src := range overlay {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, src, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	delete(overlay, filepath.Join(root, "go.mod"))
	delete(overlay, filepath.Join(root, "p", "asm.s"))
	pkgs, err := diff.LoadFiles(root, overlay)
	if err != nil {
		t.Fatal(err)
	}
	all, err := diff.FingerprintPackages(pkgs, ir.DefaultLiteralPolicy, false)
	if err != nil {
		t.Fatal(err)
	}
	render := func(rs []diff.FingerprintResult) string {
		var out []string
		for _, r := range rs {
			file := "-"
			if r.Filename != "" {
				file = filepath.Base(r.Filename)
			}
			out = append(out, fmt.Sprintf("%s %s:%d %s", r.FunctionName, file, r.Line, r.Fingerprint))
		}
		return strings.Join(out, "\n")
	}
	for _, files := range [][]string{{"a.go"}, {"b.go"}, {}, {"a.go", "b.go"}} {
		keep := func(f string) bool {
			for _, k := range files {
				if f == filepath.Join(root, "p", k) {
					return true
				}
			}
			return false
		}
		var want []diff.FingerprintResult
		for _, r := range all {
			if r.Filename == "" || keep(r.Filename) {
				want = append(want, r)
			}
		}
		got, err := diff.FingerprintPackagesWhere(pkgs, ir.DefaultLiteralPolicy, false, keep)
		if err != nil {
			t.Fatal(err)
		}
		if render(got) != render(want) {
			t.Errorf("keeping %v:\ngot:\n%s\nwant:\n%s", files, render(got), render(want))
		}
		if len(files) == 1 && files[0] == "a.go" {
			names := render(got)
			if !strings.Contains(names, "example.com/m/p.G$1 a.go:90") || strings.Contains(names, "example.com/m/p.G b.go") ||
				!strings.Contains(names, "example.com/m/p.init -:0") {
				t.Errorf("keeping a.go: want G's closure and the initializer, not G:\n%s", names)
			}
		}
		if len(files) == 1 && files[0] == "b.go" {
			names := render(got)
			if !strings.Contains(names, "(example.com/m/p.T).M b.go") || strings.Contains(names, "p.Asm") {
				t.Errorf("keeping b.go: want T's method and not the body-less Asm:\n%s", names)
			}
		}
	}
}
