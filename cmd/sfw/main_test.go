package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// BUG FIX VERIFICATION: Test for exact "_test.go" filename
		// Previously, isTestFile("_test.go") returned false due to > 8 instead of >= 8
		{
			name:     "exact _test.go filename",
			path:     "_test.go",
			expected: true,
		},
		{
			name:     "exact _test.go with directory",
			path:     "/some/path/_test.go",
			expected: true,
		},
		// Standard test file cases
		{
			name:     "standard test file",
			path:     "foo_test.go",
			expected: true,
		},
		{
			name:     "test file with path",
			path:     "/home/user/project/handler_test.go",
			expected: true,
		},
		{
			name:     "longer test file name",
			path:     "some_long_name_test.go",
			expected: true,
		},
		// Non-test file cases
		{
			name:     "regular go file",
			path:     "main.go",
			expected: false,
		},
		{
			name:     "file with test in name but not suffix",
			path:     "test_utils.go",
			expected: false,
		},
		{
			name:     "file ending in test without underscore",
			path:     "mytest.go",
			expected: false,
		},
		{
			name:     "short filename",
			path:     "a.go",
			expected: false,
		},
		{
			name:     "exactly 7 characters (less than _test.go)",
			path:     "ab_test",
			expected: false,
		},
		{
			name:     "file with _test.go in middle",
			path:     "_test.go.bak",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTestFile(tt.path)
			if result != tt.expected {
				t.Errorf("isTestFile(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestShortFunctionName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"testpkg.main", "main"},
		{"testpkg.init", "init"},
		{"testpkg.(*Type).Method", "(*Type).Method"},
		{"pkg.Func", "Func"},
		{"a.b.c", "b.c"}, // Takes first dot outside parens (legacy behavior)
		{"NoDot", "NoDot"},
		// New cases for full module paths
		{"github.com/BlackVectorOps/semantic_firewall/v2/samples/clean.StartBeacon", "StartBeacon"},
		{"github.com/BlackVectorOps/semantic_firewall/v2/samples/dirty.z", "z"},
		{"github.com/foo/bar.(*Type).Method", "(*Type).Method"},
		{"github.com/foo/bar.init", "init"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := shortFunctionName(tt.input)
			if result != tt.expected {
				t.Errorf("shortFunctionName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// setupDiffTestFiles creates temporary Go files for diff testing
func setupDiffTestFiles(t *testing.T, oldSrc, newSrc string) (oldPath, newPath string, cleanup func()) {
	t.Helper()

	dir, err := os.MkdirTemp("", "sfw-diff-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	oldPath = filepath.Join(dir, "old.go")
	newPath = filepath.Join(dir, "new.go")

	if err := os.WriteFile(oldPath, []byte(oldSrc), 0644); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("Failed to write old.go: %v", err)
	}

	if err := os.WriteFile(newPath, []byte(newSrc), 0644); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("Failed to write new.go: %v", err)
	}

	cleanup = func() { os.RemoveAll(dir) }
	return
}

func TestDiff_IdenticalFiles(t *testing.T) {
	// Workflow 1: Auto-Merge Refactor - identical logic should be preserved
	src := `package main

func add(a, b int) int {
	return a + b
}
`
	oldPath, newPath, cleanup := setupDiffTestFiles(t, src, src)
	defer cleanup()

	oldResults, err := loadAndFingerprint(oldPath)
	if err != nil {
		t.Fatalf("Failed to load old file: %v", err)
	}

	newResults, err := loadAndFingerprint(newPath)
	if err != nil {
		t.Fatalf("Failed to load new file: %v", err)
	}

	if len(oldResults) != len(newResults) {
		t.Fatalf("Result count mismatch: %d vs %d", len(oldResults), len(newResults))
	}

	// Find the add function
	var oldAdd, newAdd *FunctionFingerprint
	for _, r := range oldResults {
		if shortFunctionName(r.FunctionName) == "add" {
			fp := FunctionFingerprint{Function: r.FunctionName, Fingerprint: r.Fingerprint}
			oldAdd = &fp
			break
		}
	}
	for _, r := range newResults {
		if shortFunctionName(r.FunctionName) == "add" {
			fp := FunctionFingerprint{Function: r.FunctionName, Fingerprint: r.Fingerprint}
			newAdd = &fp
			break
		}
	}

	if oldAdd == nil || newAdd == nil {
		t.Fatal("Could not find 'add' function in results")
	}

	if oldAdd.Fingerprint != newAdd.Fingerprint {
		t.Errorf("Identical code should have matching fingerprints")
	}
}

func TestDiff_RenamedVariables(t *testing.T) {
	// Workflow 1: Auto-Merge - variable rename should be semantic-preserving
	oldSrc := `package main

func add(a, b int) int {
	result := a + b
	return result
}
`
	newSrc := `package main

func add(x, y int) int {
	sum := x + y
	return sum
}
`
	oldPath, newPath, cleanup := setupDiffTestFiles(t, oldSrc, newSrc)
	defer cleanup()

	oldResults, err := loadAndFingerprint(oldPath)
	if err != nil {
		t.Fatalf("Failed to load old file: %v", err)
	}

	newResults, err := loadAndFingerprint(newPath)
	if err != nil {
		t.Fatalf("Failed to load new file: %v", err)
	}

	// Find the add functions
	var oldFP, newFP string
	for _, r := range oldResults {
		if shortFunctionName(r.FunctionName) == "add" {
			oldFP = r.Fingerprint
		}
	}
	for _, r := range newResults {
		if shortFunctionName(r.FunctionName) == "add" {
			newFP = r.Fingerprint
		}
	}

	// Semantic equivalence: variable names don't matter
	if oldFP != newFP {
		t.Errorf("Variable rename should preserve fingerprint: old=%s, new=%s", oldFP, newFP)
	}
}

func TestDiff_LogicChange(t *testing.T) {
	// Workflow 2: Smart Diff - actual logic change should be detected
	oldSrc := `package main

func process(n int) int {
	return n * 2
}
`
	newSrc := `package main

func process(n int) int {
	if n < 0 {
		return 0
	}
	return n * 2
}
`
	oldPath, newPath, cleanup := setupDiffTestFiles(t, oldSrc, newSrc)
	defer cleanup()

	oldResults, err := loadAndFingerprint(oldPath)
	if err != nil {
		t.Fatalf("Failed to load old file: %v", err)
	}

	newResults, err := loadAndFingerprint(newPath)
	if err != nil {
		t.Fatalf("Failed to load new file: %v", err)
	}

	// Find fingerprints
	var oldFP, newFP string
	for _, r := range oldResults {
		if shortFunctionName(r.FunctionName) == "process" {
			oldFP = r.Fingerprint
		}
	}
	for _, r := range newResults {
		if shortFunctionName(r.FunctionName) == "process" {
			newFP = r.Fingerprint
		}
	}

	// Logic changed: fingerprints MUST differ
	if oldFP == newFP {
		t.Errorf("Logic change should produce different fingerprints")
	}
}

func TestDiff_FunctionAddedRemoved(t *testing.T) {
	oldSrc := `package main

func original() int {
	return 1
}
`
	newSrc := `package main

func replacement() int {
	return 2
}
`
	oldPath, newPath, cleanup := setupDiffTestFiles(t, oldSrc, newSrc)
	defer cleanup()

	oldResults, err := loadAndFingerprint(oldPath)
	if err != nil {
		t.Fatalf("Failed to load old file: %v", err)
	}

	newResults, err := loadAndFingerprint(newPath)
	if err != nil {
		t.Fatalf("Failed to load new file: %v", err)
	}

	oldNames := make(map[string]bool)
	newNames := make(map[string]bool)

	for _, r := range oldResults {
		oldNames[shortFunctionName(r.FunctionName)] = true
	}
	for _, r := range newResults {
		newNames[shortFunctionName(r.FunctionName)] = true
	}

	if !oldNames["original"] {
		t.Error("Expected 'original' in old file")
	}
	if oldNames["replacement"] {
		t.Error("Did not expect 'replacement' in old file")
	}
	if !newNames["replacement"] {
		t.Error("Expected 'replacement' in new file")
	}
	if newNames["original"] {
		t.Error("Did not expect 'original' in new file")
	}
}

func TestCompareFunctions_Preserved(t *testing.T) {
	// Test the compareFunctions helper with matching fingerprints
	src := `package main

func identity(x int) int {
	return x
}
`
	dir, err := os.MkdirTemp("", "sfw-compare-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "test.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	results, err := loadAndFingerprint(path)
	if err != nil {
		t.Fatalf("Failed to load file: %v", err)
	}

	// Find identity function
	var identityResult *struct {
		FunctionName string
		Fingerprint  string
	}
	for _, r := range results {
		if shortFunctionName(r.FunctionName) == "identity" {
			identityResult = &struct {
				FunctionName string
				Fingerprint  string
			}{r.FunctionName, r.Fingerprint}
			break
		}
	}

	if identityResult == nil {
		t.Fatal("Could not find identity function")
	}

	// Comparing same result should show preserved
	diff := compareFunctions("identity", results[0], results[0])
	if diff.Status != "preserved" {
		t.Errorf("Same function should be preserved, got: %s", diff.Status)
	}
	if !diff.FingerprintMatch {
		t.Error("FingerprintMatch should be true for identical functions")
	}
}
