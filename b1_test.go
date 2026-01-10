package semanticfw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSemanticCorruption_BinOpReuse ensures that normalization does not occur
// when the condition variable is shared, preventing semantic corruption.
func TestSemanticCorruption_BinOpReuse(t *testing.T) {
	src := `package main
func check(a, b int) bool {
	cond := a >= b
	if cond {
		return cond
	}
	return false
}
`
	tempDir, cleanup := setupTestEnv(t, "bug-sem-")
	defer cleanup()

	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	res := findResult(results, "check")
	if res == nil {
		t.Fatal("Result for 'check' not found")
	}

	// BUG FIX: When the BinOp is reused (stored in a variable and used elsewhere),
	// the normalization should be SKIPPED to avoid semantic corruption.
	// We expect the operation to REMAIN '>=' (GEQ) because mutating it would
	// corrupt the return value which also uses this BinOp.

	// Check for the presence of the original >= operator.
	if !strings.Contains(res.CanonicalIR, "BinOp >=") {
		t.Errorf("Expected BinOp >= to be preserved (normalization should be skipped when BinOp is reused).\nIR:\n%s", res.CanonicalIR)
	}
	// With the fix, we should NOT see BinOp < because the normalization was skipped.
	if strings.Contains(res.CanonicalIR, "BinOp <") {
		t.Errorf("Did NOT expect BinOp < - normalization should have been skipped for reused BinOp.\nIR:\n%s", res.CanonicalIR)
	}
}

// TestMethodDiscovery verifies that methods attached to types are found.
func TestMethodDiscovery(t *testing.T) {
	src := `package main
type MyType struct{}
func (m *MyType) MyMethod() {}
`
	tempDir, cleanup := setupTestEnv(t, "bug-method-")
	defer cleanup()
	path := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	results, err := FingerprintSource(path, src, DefaultLiteralPolicy)
	if err != nil {
		t.Fatalf("FingerprintSource failed: %v", err)
	}

	found := false
	for _, res := range results {
		if strings.Contains(res.FunctionName, "MyMethod") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Method 'MyMethod' was not discovered. Results: %v", getFunctionNames(results))
	}
}

// TestStringCommutativity verifies that string concatenation is treated as non-commutative.
func TestStringCommutativity(t *testing.T) {
	src := `package main
	func concatNormal(a, b string) string {
		return a + b
	}
	func concatReverse(a, b string) string {
		return b + a
	}
	`
	tempDir, cleanup := setupTestEnv(t, "bug-str-")
	defer cleanup()
	tempFile := filepath.Join(tempDir, "strings.go")
	os.WriteFile(tempFile, []byte(src), 0644)

	results, err := FingerprintSource(tempFile, src, KeepAllLiteralsPolicy)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	resNorm := findResult(results, "concatNormal")
	resRev := findResult(results, "concatReverse")

	if resNorm == nil || resRev == nil {
		t.Fatalf("Functions not found. Got: %v", getFunctionNames(results))
	}

	if resNorm.Fingerprint == resRev.Fingerprint {
		t.Errorf("FAIL: String concatenation should NOT be commutative.\nIR 1:\n%s\nIR 2:\n%s", resNorm.CanonicalIR, resRev.CanonicalIR)
	}
}
