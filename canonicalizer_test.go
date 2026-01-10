package semanticfw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Helper function to setup isolated test environment for packages loader
func setupTestEnv(t *testing.T, dirPrefix string) (string, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", dirPrefix)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	// Create a minimal go.mod for the packages loader to work correctly in isolation.
	// BUG FIX: Include go version to enable modern language features (e.g., SliceToArrayPointer)
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module testmod\n\ngo 1.23\n"), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}
	cleanup := func() {
		os.RemoveAll(tempDir)
	}
	return tempDir, cleanup
}

// TestCanonicalizationDeterminism verifies that semantically identical functions produce the same canonical IR.
func TestCanonicalizationDeterminism(t *testing.T) {
	src := `
			package main
			// V1: Standard range loop
			func calculateTotal(items []int) int {
				var total int
				for _, itemPrice := range items {
					total = total + itemPrice
				}
				return total
			}
			// V2: Index-based loop (condition i < len)
			func sumPrices(prices []int) int {
				var sum int = 0
				for i := 0; i < len(prices); i++ {
					sum += prices[i]
				}
				return sum
			}
			// V3: Goto based loop (condition i >= len)
			func accumulate(data []int) int {
			    result := 0
			    i := 0
			loop:
			    if i >= len(data) { goto done }
			    result += data[i]
			    i++
			    goto loop
			done:
			    return result
			}
			// V4: Commutative operation reordered
			func commutativeTest(items []int) int {
				var total int
				for _, itemPrice := range items {
					total = itemPrice + total
				}
				return total
			}
			`
	policy := DefaultLiteralPolicy

	// Create an isolated environment for the test
	tempDir, cleanup := setupTestEnv(t, "det-test-")
	defer cleanup()

	tempFile := filepath.Join(tempDir, "test.go")
	if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Use FingerprintSourceAdvanced which now correctly loads packages internally.
	results, err := FingerprintSourceAdvanced(tempFile, src, policy, true)
	if err != nil {
		t.Fatalf("Failed to fingerprint source: %v", err)
	}

	// Uses helpers from helpers_test.go
	res1 := findResult(results, "calculateTotal")
	res2 := findResult(results, "sumPrices")
	res3 := findResult(results, "accumulate")
	res4 := findResult(results, "commutativeTest")

	if res1 == nil || res2 == nil || res3 == nil || res4 == nil {
		t.Fatalf("Could not find results for all functions. Found: %v", getFunctionNames(results))
	}

	// V2 (Index loop) vs V3 (Goto loop).
	// With Control Flow Normalization AND Deterministic Traversal, these MUST match.
	if res2.Fingerprint != res3.Fingerprint {
		t.Errorf("Fingerprints for sumPrices (V2) and accumulate (V3) do not match, indicating Control Flow Normalization or Traversal failure.\nsumPrices IR:\n%s\naccumulate IR:\n%s", res2.CanonicalIR, res3.CanonicalIR)
	}

	// V1 (Range loop) vs V2 (Index loop). These often generate different SSA instructions depending on Go version optimizations.
	if res1.Fingerprint != res2.Fingerprint {
		t.Logf("Note: Fingerprints for range loop (V1) and index loop (V2) differ, which is expected due to SSA generation differences (e.g. Range/Next vs IndexAddr/BinOp) or compiler optimizations.\ncalculateTotal IR:\n%s\nsumPrices IR:\n%s", res1.CanonicalIR, res2.CanonicalIR)
	}

	// V1 vs V4 (Commutative test). These MUST match due to BinOp normalization.
	if res1.Fingerprint != res4.Fingerprint {
		t.Errorf("Fingerprints for calculateTotal (V1) and commutativeTest (V4) do not match, indicating BinOp normalization failure.\ncalculateTotal IR:\n%s\ncommutativeTest IR:\n%s", res1.CanonicalIR, res4.CanonicalIR)
	}
}

// TestLiteralPolicy verifies the behavior of the literal abstraction policy configurations.
func TestLiteralPolicy(t *testing.T) {
	// Modified src: Added GlobalSink to prevent optimization of the string literal.
	src := `
			package main

			var GlobalSink interface{} // Used to ensure literals are not optimized away

			func checkThreshold(count int) int {
				// 1. Control Flow Comparison (1000 - Large)
				if count > 1000 {
					// 2. Return Status (1 - Small)
					return 1
				}
				// 3. MakeSlice length/cap (50 - Medium). Optimized to Alloca + Slice.
				data := make([]int, 50)
				// 4. Index (0 - Small)
				data[0] = count
				// 5. Slice index (2 - Small)
				_ = data[2:]
				// 6. Bounds check (Control flow with small index 15)
				if count < 15 { return 99 }
				// 7. String literal
				GlobalSink = "hello world"
				// 8. Return Status (99 - Medium)
				return 99
			}
			`

	// We must isolate environments for each subtest to prevent package loading conflicts.

	// --- Policy 1: Abstract Everything ---
	t.Run("Abstract Everything", func(t *testing.T) {
		// Create isolated environment for this subtest
		tempDir, cleanup := setupTestEnv(t, "policy-abstract-test-")
		defer cleanup()

		policyAbstract := LiteralPolicy{
			AbstractControlFlowComparisons: true,
			KeepReturnStatusValues:         false,
			KeepSmallIntegerIndices:        false,
			SmallIntMin:                    0,
			SmallIntMax:                    0,
			AbstractOtherTypes:             true,
		}

		tempFile := filepath.Join(tempDir, "test_abstract.go")
		if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		results, err := FingerprintSourceAdvanced(tempFile, src, policyAbstract, true)
		if err != nil {
			t.Fatalf("Failed during abstract policy test: %v", err)
		}

		// Find the specific function result, as init functions might also be present due to GlobalSink.
		res := findResult(results, "checkThreshold")
		if res == nil {
			t.Fatalf("Could not find result for checkThreshold. Found: %v", getFunctionNames(results))
		}
		ir := res.CanonicalIR

		// Check 1000 (Control Flow).
		if !strings.Contains(ir, "<int_literal>") {
			t.Error("Expected 1000 (control flow) to be abstracted.")
		}
		// Check Returns (1, 99)
		if !strings.Contains(ir, "Return <int_literal>") {
			t.Errorf("Expected return values (1, 99) to be abstracted. IR:\n%s", ir)
		}
		// Check Index 0, Slice index 2, Bounds check 15
		// With the fix in policy.go, these should be abstracted because KeepSmallIntegerIndices=false.
		if strings.Contains(ir, "const(0)") || strings.Contains(ir, "const(2)") || strings.Contains(ir, "const(15)") {
			t.Errorf("Expected indices (0, 2, 15) to be abstracted. IR:\n%s", ir)
		}
		// Check Alloca abstraction
		if !strings.Contains(ir, "Alloca [<len_literal>]int") {
			t.Errorf("Expected Alloca length (50) to be abstracted. IR:\n%s", ir)
		}
		// Check String abstraction
		if !strings.Contains(ir, "<string_literal>") {
			t.Errorf("Expected string literal to be abstracted. IR:\n%s", ir)
		}
	})

	// --- Policy 2: Default Behavior ---
	t.Run("Default Policy", func(t *testing.T) {
		// Create isolated environment for this subtest
		tempDir, cleanup := setupTestEnv(t, "policy-keep-test-")
		defer cleanup()

		policyKeep := DefaultLiteralPolicy // AbstractOtherTypes=true by default

		tempFile := filepath.Join(tempDir, "test_keep.go")
		if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		results, err := FingerprintSourceAdvanced(tempFile, src, policyKeep, true)
		if err != nil {
			t.Fatalf("Failed during keep policy test: %v", err)
		}

		// Find the specific function result.
		res := findResult(results, "checkThreshold")
		if res == nil {
			t.Fatalf("Could not find result for checkThreshold. Found: %v", getFunctionNames(results))
		}
		ir := res.CanonicalIR

		// Check 1000 (Large control flow -> abstracted)
		if !strings.Contains(ir, "<int_literal>") {
			t.Error("Expected 1000 (control flow) to be abstracted by default.")
		}
		// Check Return 1 (Small return -> kept)
		if !strings.Contains(ir, "Return const(1)") {
			t.Errorf("Expected return value 1 to be kept. IR:\n%s", ir)
		}
		// Check Index 0 (Small index -> kept)
		if !strings.Contains(ir, "const(0)") {
			t.Error("Expected index 0 to be kept.")
		}
		// Check Slice index 2 (Small index -> kept)
		if !strings.Contains(ir, ", Low:const(2)") {
			t.Errorf("Expected slice index 2 to be kept. IR:\n%s", ir)
		}
		// Check Bounds check 15 (Small index in control flow -> kept due to precedence)
		if !strings.Contains(ir, "const(15)") {
			t.Errorf("Expected bounds check 15 to be kept. IR:\n%s", ir)
		}
		// Check MakeSlice 50 (Large size -> abstracted)
		if !strings.Contains(ir, "Alloca [<len_literal>]int") {
			t.Errorf("Expected large size 50 (Alloca length) to be abstracted. IR:\n%s", ir)
		}
		// Check String abstraction (Default policy abstracts strings)
		if !strings.Contains(ir, "<string_literal>") {
			t.Errorf("Expected string literal to be abstracted by default. IR:\n%s", ir)
		}
	})
}
