// Package main provides the sfw CLI tool for semantic fingerprinting of Go source files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	semanticfw "github.com/BlackVectorOps/semantic_firewall"
)

// FunctionFingerprint represents the JSON output for a single function.
type FunctionFingerprint struct {
	Function    string `json:"function"`
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
}

// FileOutput represents the JSON output for a single file.
type FileOutput struct {
	File         string                `json:"file"`
	Functions    []FunctionFingerprint `json:"functions"`
	ErrorMessage string                `json:"error,omitempty"`
}

// DiffOutput represents the JSON output for a semantic diff.
type DiffOutput struct {
	OldFile      string         `json:"old_file"`
	NewFile      string         `json:"new_file"`
	Summary      DiffSummary    `json:"summary"`
	Functions    []FunctionDiff `json:"functions"`
	ErrorMessage string         `json:"error,omitempty"`
}

// DiffSummary provides aggregate statistics for the diff.
type DiffSummary struct {
	TotalFunctions   int     `json:"total_functions"`
	Preserved        int     `json:"preserved"`
	Modified         int     `json:"modified"`
	Added            int     `json:"added"`
	Removed          int     `json:"removed"`
	SemanticMatchPct float64 `json:"semantic_match_pct"`
}

// FunctionDiff represents the semantic diff for a single function.
type FunctionDiff struct {
	Function         string   `json:"function"`
	Status           string   `json:"status"` // "preserved", "modified", "added", "removed"
	FingerprintMatch bool     `json:"fingerprint_match"`
	OldFingerprint   string   `json:"old_fingerprint,omitempty"`
	NewFingerprint   string   `json:"new_fingerprint,omitempty"`
	MatchedNodes     int      `json:"matched_nodes,omitempty"`
	AddedOps         []string `json:"added_ops,omitempty"`
	RemovedOps       []string `json:"removed_ops,omitempty"`
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `sfw - Semantic Firewall CLI

A Semantic Version Control System for Go source files.

Usage:
  sfw check [--strict] <file.go|directory>    Fingerprint a file or all .go files in a directory
  sfw diff <old.go> <new.go>                  Semantic diff between two Go files

Commands:
  check   Generate semantic fingerprints (Level 1: Signal)
          Use for auto-merge workflow - identical fingerprints prove logic preservation.
          --strict    Enable strict mode validation

  diff    Compute semantic delta using the Zipper algorithm (Level 2: Context)
          Use for smart diffs, drift monitoring, and understanding what changed.

Examples:
  sfw check main.go                Fingerprint a single file
  sfw check --strict ./pkg/        Fingerprint all Go files in strict mode
  sfw diff old.go new.go           Show semantic diff between versions

Output:
  JSON to stdout.

Workflows:
  1. Auto-Merge Refactor: If fingerprints match, logic is preserved (safe to merge).
  2. Smart Diffs: See only the actual logic changes, not cosmetic reformatting.
  3. Drift Monitor: Track semantic_match_pct over time for compliance.

`)
	}

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	// Define flag sets for subcommands
	checkCmd := flag.NewFlagSet("check", flag.ExitOnError)
	strictCheck := checkCmd.Bool("strict", false, "Enable strict mode validation")

	diffCmd := flag.NewFlagSet("diff", flag.ExitOnError)

	switch cmd {
	case "check":
		if err := checkCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if checkCmd.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "error: check requires a file or directory argument\n")
			checkCmd.Usage()
			os.Exit(1)
		}
		target := checkCmd.Arg(0)
		if err := runCheck(target, *strictCheck); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "diff":
		if err := diffCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if diffCmd.NArg() < 2 {
			fmt.Fprintf(os.Stderr, "error: diff requires two file arguments\n")
			diffCmd.Usage()
			os.Exit(1)
		}
		oldFile := diffCmd.Arg(0)
		newFile := diffCmd.Arg(1)
		if err := runDiff(oldFile, newFile); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		flag.Usage()
		os.Exit(1)
	}
}

func runCheck(target string, strictMode bool) error {
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("cannot access %s: %w", target, err)
	}

	var files []string
	if info.IsDir() {
		entries, err := filepath.Glob(filepath.Join(target, "*.go"))
		if err != nil {
			return fmt.Errorf("glob failed: %w", err)
		}
		// Filter out test files
		for _, f := range entries {
			if !isTestFile(f) {
				files = append(files, f)
			}
		}
	} else {
		files = []string{target}
	}

	if len(files) == 0 {
		return fmt.Errorf("no Go files found in %s", target)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	for _, file := range files {
		output := processFile(file, strictMode)
		if err := encoder.Encode(output); err != nil {
			return fmt.Errorf("json encode failed: %w", err)
		}
	}

	return nil
}

func processFile(filename string, strictMode bool) FileOutput {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	f, err := os.Open(absPath)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}
	defer f.Close()

	src, err := io.ReadAll(f)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	results, err := semanticfw.FingerprintSourceAdvanced(absPath, string(src), semanticfw.DefaultLiteralPolicy, strictMode)
	if err != nil {
		return FileOutput{File: filename, ErrorMessage: err.Error()}
	}

	output := FileOutput{
		File:      filename,
		Functions: make([]FunctionFingerprint, 0, len(results)),
	}

	for _, r := range results {
		output.Functions = append(output.Functions, FunctionFingerprint{
			Function:    r.FunctionName,
			Fingerprint: r.Fingerprint,
			File:        r.Filename,
			Line:        r.Line,
		})
	}

	return output
}

func isTestFile(path string) bool {
	base := filepath.Base(path)
	return len(base) >= 8 && base[len(base)-8:] == "_test.go"
}

// runDiff performs a semantic diff between two Go files using the Zipper algorithm.
func runDiff(oldFile, newFile string) error {
	// Load and fingerprint both files
	oldResults, err := loadAndFingerprint(oldFile)
	if err != nil {
		return fmt.Errorf("failed to analyze old file: %w", err)
	}

	newResults, err := loadAndFingerprint(newFile)
	if err != nil {
		return fmt.Errorf("failed to analyze new file: %w", err)
	}

	// Build lookup maps by short function name (without package prefix)
	oldByName := make(map[string]semanticfw.FingerprintResult)
	for _, r := range oldResults {
		shortName := shortFunctionName(r.FunctionName)
		oldByName[shortName] = r
	}

	newByName := make(map[string]semanticfw.FingerprintResult)
	for _, r := range newResults {
		shortName := shortFunctionName(r.FunctionName)
		newByName[shortName] = r
	}

	// Collect all unique function names
	allFunctions := make(map[string]bool)
	for name := range oldByName {
		allFunctions[name] = true
	}
	for name := range newByName {
		allFunctions[name] = true
	}

	// Compute diffs for each function
	var functionDiffs []FunctionDiff
	preserved, modified, added, removed := 0, 0, 0, 0

	for funcName := range allFunctions {
		oldResult, inOld := oldByName[funcName]
		newResult, inNew := newByName[funcName]

		switch {
		case inOld && !inNew:
			// Function was removed
			functionDiffs = append(functionDiffs, FunctionDiff{
				Function:       funcName,
				Status:         "removed",
				OldFingerprint: oldResult.Fingerprint,
			})
			removed++

		case !inOld && inNew:
			// Function was added
			functionDiffs = append(functionDiffs, FunctionDiff{
				Function:       funcName,
				Status:         "added",
				NewFingerprint: newResult.Fingerprint,
			})
			added++

		case inOld && inNew:
			// Function exists in both - compare
			diff := compareFunctions(funcName, oldResult, newResult)
			functionDiffs = append(functionDiffs, diff)
			if diff.Status == "preserved" {
				preserved++
			} else {
				modified++
			}
		}
	}

	// Calculate semantic match percentage
	total := len(allFunctions)
	matchPct := 0.0
	if total > 0 {
		matchPct = float64(preserved) / float64(total) * 100.0
	}

	output := DiffOutput{
		OldFile: oldFile,
		NewFile: newFile,
		Summary: DiffSummary{
			TotalFunctions:   total,
			Preserved:        preserved,
			Modified:         modified,
			Added:            added,
			Removed:          removed,
			SemanticMatchPct: matchPct,
		},
		Functions: functionDiffs,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// loadAndFingerprint loads a Go file and returns fingerprint results.
func loadAndFingerprint(filename string) ([]semanticfw.FingerprintResult, error) {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	src, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return semanticfw.FingerprintSource(absPath, string(src), semanticfw.DefaultLiteralPolicy)
}

// shortFunctionName extracts the function name without the package prefix.
// e.g., "testpkg.(*Type).Method" -> "(*Type).Method"
// e.g., "testpkg.init" -> "init"
func shortFunctionName(fullName string) string {
	// Find the first dot that's not inside parentheses
	depth := 0
	for i, ch := range fullName {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case '.':
			if depth == 0 {
				return fullName[i+1:]
			}
		}
	}
	return fullName
}

// compareFunctions uses the Zipper algorithm to compute semantic diff.
func compareFunctions(funcName string, oldResult, newResult semanticfw.FingerprintResult) FunctionDiff {
	diff := FunctionDiff{
		Function:       funcName,
		OldFingerprint: oldResult.Fingerprint,
		NewFingerprint: newResult.Fingerprint,
	}

	// Level 1: Quick fingerprint check
	if oldResult.Fingerprint == newResult.Fingerprint {
		diff.Status = "preserved"
		diff.FingerprintMatch = true
		return diff
	}

	// Level 2: Fingerprints differ - use Zipper for detailed analysis
	diff.FingerprintMatch = false

	oldFn := oldResult.GetSSAFunction()
	newFn := newResult.GetSSAFunction()

	if oldFn == nil || newFn == nil {
		diff.Status = "modified"
		return diff
	}

	zipper, err := semanticfw.NewZipper(oldFn, newFn, semanticfw.DefaultLiteralPolicy)
	if err != nil {
		diff.Status = "modified"
		return diff
	}

	artifacts, err := zipper.ComputeDiff()
	if err != nil {
		diff.Status = "modified"
		return diff
	}

	diff.MatchedNodes = artifacts.MatchedNodes
	diff.AddedOps = artifacts.Added
	diff.RemovedOps = artifacts.Removed

	if artifacts.Preserved {
		// Zipper says semantically equivalent despite different fingerprints
		// (edge case with different canonicalization paths)
		diff.Status = "preserved"
	} else {
		diff.Status = "modified"
	}

	return diff
}
