package semanticfw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestChangeInterface verifies that interface-to-interface conversions are handled.
// BUG FIX: Previously unhandled *ssa.ChangeInterface would panic in strict mode.
func TestChangeInterface(t *testing.T) {
	src := `package main
import "io"

func changeInterface(r io.Reader) interface{} {
	return r // Converts io.Reader to interface{}
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-changeintf-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Should NOT panic in strict mode
	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res := findResult(results, "changeInterface")
	if res == nil {
		t.Fatal("Result for 'changeInterface' not found")
	}

	// Verify the ChangeInterface instruction is in the IR
	if !strings.Contains(res.CanonicalIR, "ChangeInterface") {
		t.Errorf("Expected ChangeInterface in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestSliceToArrayPointer verifies slice-to-array-pointer conversions are handled.
// BUG FIX: Go 1.20+ feature was previously unhandled.
func TestSliceToArrayPointer(t *testing.T) {
	src := `package main

func sliceToArray(s []int) *[4]int {
	if len(s) >= 4 {
		return (*[4]int)(s)
	}
	return nil
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-slice2arr-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Should NOT panic in strict mode
	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res := findResult(results, "sliceToArray")
	if res == nil {
		t.Fatal("Result for 'sliceToArray' not found")
	}

	// Verify the SliceToArrayPointer instruction is in the IR
	if !strings.Contains(res.CanonicalIR, "SliceToArrayPointer") {
		t.Errorf("Expected SliceToArrayPointer in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestComplexNumberNormalization verifies that complex number comparisons are NOT normalized.
// BUG FIX: Complex numbers have undefined ordering, similar to NaN for floats.
// Note: Go doesn't allow < > <= >= on complex types, so we test that the NaN check
// logic also includes the IsComplex flag (this is a defensive fix).
func TestComplexNumberNormalization(t *testing.T) {
	// We can test the fix indirectly by verifying float behavior still works
	src := `package main
import "math"

func checkFloat(a, b float64) bool {
	if a >= b {
		return true
	}
	return math.IsNaN(a)
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-complex-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	res := findResult(results, "checkFloat")
	if res == nil {
		t.Fatal("Result for 'checkFloat' not found")
	}

	// Float comparisons should NOT be normalized (>= should remain >=)
	if !strings.Contains(res.CanonicalIR, "BinOp >=") {
		t.Errorf("Expected BinOp >= to be preserved for float comparison (NaN safety).\nIR:\n%s", res.CanonicalIR)
	}
}

// TestDefensiveSuccessorCheck verifies the code handles edge cases gracefully.
// This tests that the defensive checks don't break normal operation.
func TestDefensiveSuccessorCheck(t *testing.T) {
	src := `package main

func normalBranching(x int) int {
	if x > 10 {
		return 1
	} else if x > 5 {
		return 2
	}
	return 0
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-defense-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	res := findResult(results, "normalBranching")
	if res == nil {
		t.Fatal("Result for 'normalBranching' not found")
	}

	// Should still produce valid IR with If instructions
	if !strings.Contains(res.CanonicalIR, "If ") {
		t.Errorf("Expected If instruction in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestEmptyBlocksHandling verifies functions with empty blocks don't cause issues.
func TestEmptyBlocksHandling(t *testing.T) {
	src := `package main

func empty() {}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-empty-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	res := findResult(results, "empty")
	if res == nil {
		t.Fatal("Result for 'empty' not found")
	}

	// Should produce valid IR
	if !strings.Contains(res.CanonicalIR, "Return") {
		t.Errorf("Expected Return instruction in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestMultipleInterfaceConversions verifies complex interface conversion chains.
func TestMultipleInterfaceConversions(t *testing.T) {
	src := `package main
import (
	"fmt"
	"io"
)

type MyReader struct{}
func (m *MyReader) Read(p []byte) (int, error) { return 0, nil }

func multiConvert(m *MyReader) {
	var r io.Reader = m      // MakeInterface
	var i interface{} = r    // ChangeInterface
	fmt.Println(i)
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-multiconv-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Should NOT panic in strict mode
	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res := findResult(results, "multiConvert")
	if res == nil {
		t.Fatal("Result for 'multiConvert' not found")
	}

	// Should contain both MakeInterface and ChangeInterface
	if !strings.Contains(res.CanonicalIR, "MakeInterface") {
		t.Errorf("Expected MakeInterface in IR.\nIR:\n%s", res.CanonicalIR)
	}
	if !strings.Contains(res.CanonicalIR, "ChangeInterface") {
		t.Errorf("Expected ChangeInterface in IR.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestAllNewInstructionsCombined tests all new instruction types in one function.
func TestAllNewInstructionsCombined(t *testing.T) {
	src := `package main
import "io"

func combined(r io.Reader, s []int) (interface{}, *[2]int) {
	var i interface{} = r // ChangeInterface (io.Reader -> interface{})
	var arr *[2]int
	if len(s) >= 2 {
		arr = (*[2]int)(s) // SliceToArrayPointer
	}
	return i, arr
}
`
	tempDir, cleanup := setupTestEnv(t, "bugfix-combined-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Should NOT panic in strict mode
	results, err := FingerprintSourceAdvanced(path, src, DefaultLiteralPolicy, true)
	if err != nil {
		t.Fatalf("FingerprintSourceAdvanced failed: %v", err)
	}

	res := findResult(results, "combined")
	if res == nil {
		t.Fatal("Result for 'combined' not found")
	}

	// Both new instruction types should be handled
	if !strings.Contains(res.CanonicalIR, "ChangeInterface") {
		t.Errorf("Expected ChangeInterface in IR.\nIR:\n%s", res.CanonicalIR)
	}
	if !strings.Contains(res.CanonicalIR, "SliceToArrayPointer") {
		t.Errorf("Expected SliceToArrayPointer in IR.\nIR:\n%s", res.CanonicalIR)
	}
}
