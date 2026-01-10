package semanticfw

import (
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestFingerprinterOrchestration verifies the high-level logic, sorting, and recursion.
func TestFingerprinterOrchestration(t *testing.T) {
	src := `
		package main

		var X int = 5

		func init() { X = 1 }

		func Zeta() {}

		func Alpha() {
			f := func() {}
			f()
		}
		`
	policy := DefaultLiteralPolicy

	// Create an isolated environment for the test (Uses helper from canonicalizer_test.go)
	tempDir, cleanup := setupTestEnv(t, "orch-test-")
	defer cleanup()

	tempFile := filepath.Join(tempDir, "orchestration.go")
	if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Use FingerprintSource (which internally loads packages)
	results, err := FingerprintSource(tempFile, src, policy)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	// Expecting Alpha, Alpha$1 (anon func), Zeta, and init#1 (user defined init).
	if len(results) != 4 {
		t.Fatalf("Expected 4 results (excluding synthetic init), got %d. Names: %v", len(results), getFunctionNames(results))
	}

	initName := ""
	actualOrder := getFunctionNames(results)
	for _, name := range actualOrder {
		if strings.Contains(name, "init") {
			initName = name
			break
		}
	}

	if initName == "" {
		t.Fatalf("Could not find user-defined init function (e.g., init#1). Names: %v", actualOrder)
	}

	// Verify deterministic sorting (alphabetical).
	// Function names are now package-qualified (testmod.FunctionName).
	expectedOrder := []string{"testmod.Alpha", "testmod.Alpha$1", "testmod.Zeta", initName}
	sort.Strings(expectedOrder)

	matches := true
	if len(actualOrder) != len(expectedOrder) {
		matches = false
	} else {
		for i := range expectedOrder {
			if actualOrder[i] != expectedOrder[i] {
				matches = false
				break
			}
		}
	}

	if !matches {
		t.Errorf("Expected results sorted alphabetically %v. Got: %v", expectedOrder, actualOrder)
	}
}

// TestPositionalInformation verifies that the Pos field is correctly populated when using FingerprintPackages.
func TestPositionalInformation(t *testing.T) {
	src := `package main
// Line 2
func Alpha() {} // Pos should point here
// Line 4
func Beta() {
	_ = func() {} // Anon func Pos
}
`
	// Create an isolated environment for the test
	tempDir, cleanup := setupTestEnv(t, "pos-test-")
	defer cleanup()

	tempFile := filepath.Join(tempDir, "pos.go")
	if err := os.WriteFile(tempFile, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// 1. Load the package using the standard loader (this simulates how the patcher works).
	cfg := &packages.Config{
		Dir:  tempDir,
		Mode: packages.LoadAllSyntax,
		Fset: token.NewFileSet(), // Create the FileSet here
	}
	pkgs, err := packages.Load(cfg, "file="+tempFile)
	if err != nil {
		t.Fatalf("Failed to load packages: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("No packages loaded.")
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("Errors found in loaded packages.")
	}

	// 2. Generate Fingerprints using the loaded packages.
	results, err := FingerprintPackages(pkgs, DefaultLiteralPolicy, false)
	if err != nil {
		t.Fatalf("Failed to fingerprint packages: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("Expected 3 results (Alpha, Beta, Beta$1), got %d. Names: %v", len(results), getFunctionNames(results))
	}

	// 3. Verify positions using the FileSet from the loader.
	fset := cfg.Fset
	for _, res := range results {
		posInfo := fset.Position(res.Pos)
		expectedLine := 0
		// Handle both package-qualified and simple function names
		funcName := res.FunctionName
		if idx := strings.LastIndex(funcName, "."); idx >= 0 {
			funcName = funcName[idx+1:]
		}
		switch funcName {
		case "Alpha":
			expectedLine = 3
		case "Beta":
			expectedLine = 5
		case "Beta$1": // Anonymous function
			expectedLine = 6
		}

		if posInfo.Line != expectedLine {
			t.Errorf("Line number mismatch for %s. Expected: %d, Got: %d (Pos: %d)", res.FunctionName, expectedLine, posInfo.Line, res.Pos)
		}
	}
}

// TestDependencyResolution confirms that the builder can resolve third-party imports.
func TestDependencyResolution(t *testing.T) {
	// This test requires network access.
	if testing.Short() {
		t.Skip("Skipping dependency resolution test in short mode.")
	}

	// Create an isolated environment for the test
	tempDir, cleanup := setupTestEnv(t, "dep-test-")
	defer cleanup()

	// We must ensure the go.mod created by setupTestEnv is used.
	goModPath := filepath.Join(tempDir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		t.Fatalf("go.mod not found: %v", err)
	}

	srcWithDep := `
package main
import "github.com/google/uuid"
func generateID() string {
	return uuid.New().String()
}
`
	sourceFilePath := filepath.Join(tempDir, "main.go")
	if err := os.WriteFile(sourceFilePath, []byte(srcWithDep), 0644); err != nil {
		t.Fatalf("Failed to write source file: %v", err)
	}

	// Crucial step: Run 'go mod tidy' or 'go get' to download the dependency.
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = tempDir // Run the command in our temporary module directory.
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to run 'go mod tidy': %v\nOutput: %s", err, string(output))
	}

	// Attempt to fingerprint. If dependencies weren't resolved, this will fail during the packages.Load phase.
	_, err := FingerprintSource(sourceFilePath, srcWithDep, DefaultLiteralPolicy)

	if err != nil {
		t.Errorf("Expected dependency resolution to succeed, but got an error: %v", err)
	}
}

// TestErrorHandling verifies that the package correctly handles invalid inputs.
// We must ensure isolation for each test case to prevent cross-contamination.
func TestErrorHandling(t *testing.T) {

	t.Run("Empty Input", func(t *testing.T) {
		// Setup isolated env
		tempDir, cleanup := setupTestEnv(t, "err-empty-input-")
		defer cleanup()

		_, err := FingerprintSource(filepath.Join(tempDir, "empty.go"), "", DefaultLiteralPolicy)
		if err == nil {
			t.Error("Expected an error for empty input, but got nil.")
		}
		if !strings.Contains(err.Error(), "input source code is empty") {
			t.Errorf("Expected 'input source code is empty' error, got: %v", err)
		}
	})

	t.Run("Syntax Error", func(t *testing.T) {
		// Setup isolated env
		tempDir, cleanup := setupTestEnv(t, "err-syntax-")
		defer cleanup()

		src := `package main; func main() { missing_bracket `
		tempFile := filepath.Join(tempDir, "syntax_error.go")
		os.WriteFile(tempFile, []byte(src), 0644)
		_, err := FingerprintSource(tempFile, src, DefaultLiteralPolicy)
		if err == nil {
			t.Error("Expected a syntax error, but got nil.")
		}
		if !strings.Contains(err.Error(), "packages contain errors:") {
			t.Errorf("Expected 'packages contain errors' error, got: %v", err)
		}
	})

	t.Run("Type Error", func(t *testing.T) {
		// Setup isolated env
		tempDir, cleanup := setupTestEnv(t, "err-type-")
		defer cleanup()

		src := `package main; func main() { var x int = "string" }`
		tempFile := filepath.Join(tempDir, "type_error.go")
		os.WriteFile(tempFile, []byte(src), 0644)
		_, err := FingerprintSource(tempFile, src, DefaultLiteralPolicy)
		if err == nil {
			t.Error("Expected a type error, but got nil.")
		}
		if !strings.Contains(err.Error(), "packages contain errors:") {
			t.Errorf("Expected 'packages contain errors' error, got: %v", err)
		}
	})

	t.Run("Empty Package", func(t *testing.T) {
		// Setup isolated env
		tempDir, cleanup := setupTestEnv(t, "err-empty-pkg-")
		defer cleanup()

		src := `package main`
		tempFile := filepath.Join(tempDir, "empty_pkg.go")
		os.WriteFile(tempFile, []byte(src), 0644)
		results, err := FingerprintSource(tempFile, src, DefaultLiteralPolicy)
		if err != nil {
			t.Errorf("Did not expect error for empty package, but got: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("Expected 0 fingerprints for an empty package, but got %d. Names: %v", len(results), getFunctionNames(results))
		}
	})
}

// TestStrictMode verifies that StrictMode configuration is respected.
// Since ssa.Select is now implemented, this test confirms it works in both modes without panic.
func TestStrictMode(t *testing.T) {
	src := `
package main
func waitFor(ch1, ch2 chan bool) {
	select {
	case <-ch1:
		return
	case <-ch2:
		return
	default:
		return
	}
}
`
	policy := DefaultLiteralPolicy

	// Helper to run the test in an isolated environment
	runTest := func(t *testing.T, strictMode bool) {
		// Setup isolated env
		modeStr := "nonstrict"
		if strictMode {
			modeStr = "strict"
		}
		tempDir, cleanup := setupTestEnv(t, "strict-"+modeStr+"-")
		defer cleanup()

		tempFile := filepath.Join(tempDir, "test_"+modeStr+".go")
		os.WriteFile(tempFile, []byte(src), 0644)

		// Ensure panic is caught if it occurs (e.g., if an instruction is unexpectedly unhandled in strict mode)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Strict mode (enabled=%v) panicked unexpectedly: %v", strictMode, r)
			}
		}()

		results, err := FingerprintSourceAdvanced(tempFile, src, policy, strictMode)
		if err != nil {
			t.Fatalf("Mode (strict=%v) failed: %v", strictMode, err)
		}
		res := findResult(results, "waitFor")
		if res == nil {
			t.Fatal("Could not find result for 'waitFor' function.")
		}

		// Verify that the Select instruction is present and correctly canonicalized.
		if !strings.Contains(res.CanonicalIR, "Select [non-blocking]") {
			t.Errorf("Expected 'Select [non-blocking]' instruction in IR. Got:\n%s", res.CanonicalIR)
		}
	}

	t.Run("Non-Strict Mode", func(t *testing.T) {
		runTest(t, false)
	})

	t.Run("Strict Mode", func(t *testing.T) {
		// This should succeed now that Select is handled.
		runTest(t, true)
	})
}
