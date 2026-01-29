package diff_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/testutil"
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
