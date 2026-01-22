// -- semantic_firewall/cmd/sfw/diff_test.go --
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -- Test Helpers --

// setupDiffTestFiles creates temporary Go files for diff testing within dedicated subdirectories.
func setupDiffTestFiles(t *testing.T, oldSrc, newSrc string) (oldPath, newPath string, cleanup func()) {
	t.Helper()

	// creates a dedicated temp directory for this test case
	dir, err := os.MkdirTemp("", "sfw-diff-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create subdirectories for isolation
	dirV1 := filepath.Join(dir, "v1")
	dirV2 := filepath.Join(dir, "v2")
	if err := os.MkdirAll(dirV1, 0755); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("Failed to create v1 dir: %v", err)
	}
	if err := os.MkdirAll(dirV2, 0755); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("Failed to create v2 dir: %v", err)
	}

	oldPath = filepath.Join(dirV1, "old.go")
	newPath = filepath.Join(dirV2, "new.go")

	// writes files atomically
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

// -- Diff Workflow Tests --

func TestComputeDiff_Integration(t *testing.T) {
	// verifies that the full diff workflow handles a complex scenario:
	// 1. One function unmodified (preserved)
	// 2. One function renamed but logic matches (renamed)
	// 3. One function logic changed (modified)
	// 4. One function added (added)
	// 5. One function removed (removed)

	oldSrc := `package main

import "fmt"

func keepMe() int { return 1 }
func renameMe() int { return 100 }
func changeMe() int { return 50 }
func deleteMe() { fmt.Println("bye") }
`

	newSrc := `package main

func keepMe() int { return 1 }
func iHaveBeenRenamed() int { return 100 }
func changeMe() int { 
	if true { return 51 }
	return 0
}
func newGuy() string { return "hello" }
`

	oldPath, newPath, cleanup := setupDiffTestFiles(t, oldSrc, newSrc)
	defer cleanup()

	diff, err := computeDiff(oldPath, newPath)
	if err != nil {
		t.Fatalf("computeDiff returned error: %v", err)
	}

	// Manually count statuses, ignoring synthetic 'init' functions which cause noise
	stats := map[string]int{
		"preserved": 0, "renamed": 0, "modified": 0, "added": 0, "removed": 0,
	}

	for _, f := range diff.Functions {
		if f.Function == "init" || strings.Contains(f.Function, ".init") {
			continue
		}
		stats[f.Status]++
	}

	if stats["preserved"] != 1 {
		t.Errorf("Expected 1 preserved function (keepMe), got %d", stats["preserved"])
	}

	if stats["renamed"] != 1 {
		t.Errorf("Expected 1 renamed function (renameMe->iHaveBeenRenamed), got %d", stats["renamed"])
	}

	if stats["modified"] != 1 {
		t.Errorf("Expected 1 modified function (changeMe), got %d", stats["modified"])
	}

	if stats["added"] != 1 {
		t.Errorf("Expected 1 added function (newGuy), got %d", stats["added"])
	}

	if stats["removed"] != 1 {
		t.Errorf("Expected 1 removed function (deleteMe), got %d", stats["removed"])
	}
}

func TestComputeDiff_TopologyRisk(t *testing.T) {
	// verifies that structural changes trigger risk scores.
	// We introduce a loop and a panic to trigger specific topology deltas.

	oldSrc := `package main
func riskCheck() {
    a := 1
    _ = a
}
`
	// Use a conditional panic so the CFG retains the loop back-edge.
	newSrc := `package main
func riskCheck() {
    for i := 0; i < 10; i++ {
		if i > 100 {
        	panic("structure changed")
		}
    }
}
`

	oldPath, newPath, cleanup := setupDiffTestFiles(t, oldSrc, newSrc)
	defer cleanup()

	diff, err := computeDiff(oldPath, newPath)
	if err != nil {
		t.Fatalf("computeDiff failed: %v", err)
	}

	var targetDiff FunctionDiff
	found := false
	for _, f := range diff.Functions {
		if f.Function == "riskCheck" {
			targetDiff = f
			found = true
			break
		}
	}

	if !found {
		t.Fatal("Could not find 'riskCheck' in diff output")
	}

	if targetDiff.Status != "modified" {
		t.Errorf("Expected status 'modified', got '%s'", targetDiff.Status)
	}

	// verifies that risk score is non-zero due to added loops and panic
	if targetDiff.RiskScore <= 0 {
		t.Errorf("Expected positive risk score for added control structures, got %d", targetDiff.RiskScore)
	}

	// checks specific delta strings based on calculateTopologyDelta logic
	if !strings.Contains(targetDiff.TopologyDelta, "Loops+") {
		t.Errorf("Expected TopologyDelta to contain 'Loops+', got %s", targetDiff.TopologyDelta)
	}
	if !strings.Contains(targetDiff.TopologyDelta, "AddedPanic") {
		t.Errorf("Expected TopologyDelta to contain 'AddedPanic', got %s", targetDiff.TopologyDelta)
	}
}

func TestComputeDiff_AddedFunctionRiskAnalysis(t *testing.T) {
	// verifies that newly added functions are analyzed for topology risk
	// (The bypass vulnerability fix logic).

	oldSrc := `package main
// empty
`
	// new function has a loop, which adds risk points
	newSrc := `package main
func dangerousNewFunc() {
    for {
        go func() {
            panic("boom")
        }()
    }
}
`

	oldPath, newPath, cleanup := setupDiffTestFiles(t, oldSrc, newSrc)
	defer cleanup()

	diff, err := computeDiff(oldPath, newPath)
	if err != nil {
		t.Fatalf("computeDiff failed: %v", err)
	}

	// FIX: Expected 2 added functions because SSA extracts the anon closure in 'go func'
	if diff.Summary.Added != 2 {
		t.Fatalf("Expected 2 added functions (parent + closure), got %d", diff.Summary.Added)
	}

	// Find the parent function
	var addedFunc FunctionDiff
	for _, f := range diff.Functions {
		if f.Function == "dangerousNewFunc" {
			addedFunc = f
			break
		}
	}

	// verifies that the added function is not just "NewFunction" but has detected topology
	if addedFunc.Function != "dangerousNewFunc" {
		t.Errorf("Expected dangerousNewFunc to be present, got: %v", diff.Functions)
	}

	// verify risk score is high (Loop=10, Goroutine=15, Panic=5 => should be >= 30)
	if addedFunc.RiskScore < 10 {
		t.Errorf("Expected high risk score for complex added function, got %d", addedFunc.RiskScore)
	}

	if !strings.Contains(addedFunc.TopologyDelta, "AddedGoroutine") {
		t.Errorf("Expected detection of Goroutine in added function, got %s", addedFunc.TopologyDelta)
	}
}

func TestComputeDiff_RenamingHeuristic(t *testing.T) {
	// verifies that function matching works via topology even if names differ completely.

	oldSrc := `package main
func worker(data int) int {
    if data > 10 {
        return data * 2
    }
    return data + 1
}
`
	// same structure, different name and variable names
	newSrc := `package main
func processPayload(payload int) int {
    if payload > 10 {
        return payload * 2
    }
    return payload + 1
}
`

	oldPath, newPath, cleanup := setupDiffTestFiles(t, oldSrc, newSrc)
	defer cleanup()

	diff, err := computeDiff(oldPath, newPath)
	if err != nil {
		t.Fatalf("computeDiff failed: %v", err)
	}

	// If semanticfw.MatchFunctionsByTopology works, this should be 1 renamed, 0 added, 0 removed.
	if diff.Summary.RenamedFunctions != 1 {
		t.Errorf("Expected 1 renamed function, got %d", diff.Summary.RenamedFunctions)
	}

	if diff.Summary.Added != 0 || diff.Summary.Removed != 0 {
		t.Errorf("Renaming detection failed. Added: %d, Removed: %d", diff.Summary.Added, diff.Summary.Removed)
	}

	// verifies the display format in the diff entry
	expectedName := "worker → processPayload"
	found := false
	for _, f := range diff.Functions {
		if strings.Contains(f.Function, "worker") && strings.Contains(f.Function, "processPayload") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected function entry '%s', but did not find it in %v", expectedName, diff.Functions)
	}
}

func TestCalculateTopologyDelta_Direct(t *testing.T) {
	delta, score := calculateTopologyDelta(nil, nil)
	if delta != "Unknown" || score != 0 {
		t.Errorf("Expected Unknown/0 for nil inputs, got %s/%d", delta, score)
	}
}
