// Package main provides the sfw CLI tool for semantic fingerprinting of Go source files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Represents the JSON output for a single function.
type FunctionFingerprint struct {
	Function    string `json:"function"`
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
}

// Represents the JSON output for a single file.
type FileOutput struct {
	File         string                  `json:"file"`
	Functions    []FunctionFingerprint   `json:"functions"`
	ScanResults  []semanticfw.ScanResult `json:"scan_results,omitempty"` // Unified Pipeline: security alerts
	ErrorMessage string                  `json:"error,omitempty"`
}

// Represents the JSON output for a semantic diff.
type DiffOutput struct {
	OldFile      string         `json:"old_file"`
	NewFile      string         `json:"new_file"`
	Summary      DiffSummary    `json:"summary"`
	Functions    []FunctionDiff `json:"functions"`
	ErrorMessage string         `json:"error,omitempty"`
	// Topology matching info
	TopologyMatches []TopologyMatchInfo `json:"topology_matches,omitempty"`
}

// Describes a function pair matched by structural similarity.
type TopologyMatchInfo struct {
	OldFunction   string  `json:"old_function"`
	NewFunction   string  `json:"new_function"`
	Similarity    float64 `json:"similarity"`
	MatchedByName bool    `json:"matched_by_name"`
	OldTopology   string  `json:"old_topology,omitempty"`
	NewTopology   string  `json:"new_topology,omitempty"`
}

// Provides aggregate statistics for the diff.
type DiffSummary struct {
	TotalFunctions     int     `json:"total_functions"`
	Preserved          int     `json:"preserved"`
	Modified           int     `json:"modified"`
	Added              int     `json:"added"`
	Removed            int     `json:"removed"`
	SemanticMatchPct   float64 `json:"semantic_match_pct"`
	TopologyMatchedPct float64 `json:"topology_matched_pct,omitempty"` // % matched by structure
	RenamedFunctions   int     `json:"renamed_functions,omitempty"`    // # functions matched by topology, not name
	HighRiskChanges    int     `json:"high_risk_changes,omitempty"`    // Risk-Aware: changes adding calls/loops
}

// Represents the semantic diff for a single function.
type FunctionDiff struct {
	Function         string   `json:"function"`
	Status           string   `json:"status"` // "preserved", "modified", "added", "removed"
	FingerprintMatch bool     `json:"fingerprint_match"`
	OldFingerprint   string   `json:"old_fingerprint,omitempty"`
	NewFingerprint   string   `json:"new_fingerprint,omitempty"`
	MatchedNodes     int      `json:"matched_nodes,omitempty"`
	AddedOps         []string `json:"added_ops,omitempty"`
	RemovedOps       []string `json:"removed_ops,omitempty"`
	RiskScore        int      `json:"risk_score,omitempty"`     // Risk-Aware: higher = more suspicious change
	TopologyDelta    string   `json:"topology_delta,omitempty"` // Risk-Aware: structural change summary
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `sfw - Semantic Firewall CLI

A Semantic Malware Scanner for Go source files.

Usage:
  sfw check [--strict] <file.go|directory>    Fingerprint a file or all .go files in a directory
  sfw diff <old.go> <new.go>                  Semantic diff between two Go files
  sfw index <file.go> --name <name> --severity <level> --db <path>
                                              Index a malware sample into the signature database
  sfw scan <file.go|directory> --db <path>    Scan code against the signature database
  sfw migrate --from <json> --to <db>         Migrate JSON signatures to BoltDB
  sfw stats --db <path>                       Show database statistics

Commands:
  check   Generate semantic fingerprints (Level 1: Signal)
          Use for auto-merge workflow - identical fingerprints prove logic preservation.
          --strict    Enable strict mode validation

  diff    Compute semantic delta using the Zipper algorithm (Level 2: Context)
          Use for smart diffs, drift monitoring, and understanding what changed.

  index   Index a reference malware sample (Lab Phase)
          Generates topology hash + entropy score and adds to signature database.
          --name        Signature name (required)
          --severity    CRITICAL, HIGH, MEDIUM, LOW (default: HIGH)
          --category    Signature category (default: malware)
          --db          Path to database (default: ./signatures.db)
                        Use .db extension for BoltDB, .json for legacy JSON

  scan    Scan target code for malware signatures (Hunter Phase)
          Matches function topologies and entropy against known signatures.
          Uses O(1) exact topology matching + O(M) entropy range scanning.
          --db          Path to database (default: ./signatures.db)
          --threshold   Match confidence threshold 0.0-1.0 (default: 0.75)
          --exact       Use exact topology matching only (fastest, no fuzzy)
          --deps        Scan imported dependencies (requires network/module cache)
          --deps-depth  How deep to scan dependencies: direct, transitive (default: direct)

  migrate Migrate legacy JSON database to BoltDB format.
          --from        Path to source signatures.json
          --to          Path to destination signatures.db

  stats   Display database statistics.
          --db          Path to BoltDB database

Examples:
  sfw check main.go                          Fingerprint a single file
  sfw check --strict ./pkg/                  Fingerprint all Go files in strict mode
  sfw diff old.go new.go                     Show semantic diff between versions
  sfw index malware.go --name "Beacon_v1" --severity CRITICAL
  sfw scan suspicious.go --db signatures.db
  sfw scan ./cmd/ --deps --db signatures.db  Scan code AND its imported dependencies
  sfw scan . --deps --deps-depth transitive  Deep scan all transitive dependencies
  sfw migrate --from signatures.json --to signatures.db
  sfw stats --db signatures.db

Output:
  JSON to stdout.

Database Formats:
  BoltDB (.db):  Recommended for production. O(1) lookups, ACID transactions.
  JSON (.json):  Legacy format. Simple but slow for large databases.

Workflows:
  1. Auto-Merge Refactor: If fingerprints match, logic is preserved (safe to merge).
  2. Smart Diffs: See only the actual logic changes, not cosmetic reformatting.
  3. Drift Monitor: Track semantic_match_pct over time for compliance.
  4. Malware Scanning: Index known malware, scan unknown code at scale.

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
	checkScan := checkCmd.Bool("scan", false, "Enable security scanning (unified pipeline)")
	checkDB := checkCmd.String("db", "", "Path to signatures database for scanning (default: auto-detect)")

	diffCmd := flag.NewFlagSet("diff", flag.ExitOnError)

	indexCmd := flag.NewFlagSet("index", flag.ExitOnError)
	indexName := indexCmd.String("name", "", "Signature name (required)")
	indexSeverity := indexCmd.String("severity", "HIGH", "Severity level: CRITICAL, HIGH, MEDIUM, LOW")
	indexCategory := indexCmd.String("category", "malware", "Signature category")
	indexDB := indexCmd.String("db", "", "Path to signatures database (default: auto-detect)")

	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scanDB := scanCmd.String("db", "", "Path to signatures database (default: auto-detect)")
	scanThreshold := scanCmd.Float64("threshold", 0.75, "Match confidence threshold (0.0-1.0)")
	scanExact := scanCmd.Bool("exact", false, "Use exact topology matching only (fastest)")
	scanDeps := scanCmd.Bool("deps", false, "Scan imported dependencies")
	scanDepsDepth := scanCmd.String("deps-depth", "direct", "Dependency depth: direct or transitive")

	migrateCmd := flag.NewFlagSet("migrate", flag.ExitOnError)
	migrateFrom := migrateCmd.String("from", "", "Source JSON database path")
	migrateTo := migrateCmd.String("to", "", "Destination BoltDB database path")

	statsCmd := flag.NewFlagSet("stats", flag.ExitOnError)
	statsDB := statsCmd.String("db", "", "Path to BoltDB database (default: auto-detect)")

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
		if err := runCheck(target, *strictCheck, *checkScan, resolveDBPath(*checkDB)); err != nil {
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
	case "index":
		if err := indexCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if indexCmd.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "error: index requires a file argument\n")
			indexCmd.Usage()
			os.Exit(1)
		}
		if *indexName == "" {
			fmt.Fprintf(os.Stderr, "error: --name is required for index command\n")
			os.Exit(1)
		}
		target := indexCmd.Arg(0)
		if err := runIndex(target, *indexName, *indexSeverity, *indexCategory, resolveDBPath(*indexDB)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "scan":
		if err := scanCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if scanCmd.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "error: scan requires a file or directory argument\n")
			scanCmd.Usage()
			os.Exit(1)
		}
		target := scanCmd.Arg(0)
		scanOpts := ScanOptions{
			DBPath:    resolveDBPath(*scanDB),
			Threshold: *scanThreshold,
			ExactOnly: *scanExact,
			ScanDeps:  *scanDeps,
			DepsDepth: *scanDepsDepth,
		}
		if err := runScan(target, scanOpts); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "migrate":
		if err := migrateCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if *migrateFrom == "" || *migrateTo == "" {
			fmt.Fprintf(os.Stderr, "error: migrate requires --from and --to arguments\n")
			migrateCmd.Usage()
			os.Exit(1)
		}
		if err := runMigrate(*migrateFrom, *migrateTo); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "stats":
		if err := statsCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if err := runStats(resolveDBPath(*statsDB)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		if suggestion := suggestCommand(cmd); suggestion != "" {
			fmt.Fprintf(os.Stderr, "Did you mean '%s'?\n\n", suggestion)
		}
		flag.Usage()
		os.Exit(1)
	}
}

func levenshtein(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	n, m := len(r1), len(r2)
	if n > m {
		r1, r2 = r2, r1
		n, m = m, n
	}
	current := make([]int, n+1)
	for i := 0; i <= n; i++ {
		current[i] = i
	}
	for j := 1; j <= m; j++ {
		previous := current[0]
		current[0] = j
		for i := 1; i <= n; i++ {
			temp := current[i]
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			current[i] = min(min(current[i-1]+1, current[i]+1), previous+cost)
			previous = temp
		}
	}
	return current[n]
}

func suggestCommand(cmd string) string {
	commands := []string{"check", "diff", "index", "scan", "migrate", "stats"}
	bestMatch := ""
	minDist := 100 // Arbitrary high number

	for _, c := range commands {
		dist := levenshtein(cmd, c)
		if dist < minDist {
			minDist = dist
			bestMatch = c
		}
	}

	// Only suggest if distance is small (e.g. <= 2) and less than half the command length
	if minDist <= 2 {
		return bestMatch
	}
	return ""
}

// SYNERGY: Unified Pipeline - Integrity Check + Security Scanning
func runCheck(target string, strictMode bool, enableScan bool, dbPath string) error {
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

	// Open scanner if security scanning is enabled
	var scanner *semanticfw.BoltScanner
	if enableScan {
		if isBoltDB(dbPath) {
			opts := semanticfw.DefaultBoltScannerOptions()
			opts.ReadOnly = true
			scanner, err = semanticfw.NewBoltScanner(dbPath, opts)
			if err != nil {
				// Warn but continue without scanning
				fmt.Fprintf(os.Stderr, "warning: could not open signature database: %v\n", err)
			} else {
				defer scanner.Close()
			}
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	for _, file := range files {
		output := processFile(file, strictMode, scanner)
		if err := encoder.Encode(output); err != nil {
			return fmt.Errorf("json encode failed: %w", err)
		}
	}

	return nil
}

func processFile(filename string, strictMode bool, scanner *semanticfw.BoltScanner) FileOutput {
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

		// SYNERGY: Unified Pipeline - scan each function for malware signatures
		if scanner != nil {
			fn := r.GetSSAFunction()
			if fn != nil {
				topo := semanticfw.ExtractTopology(fn)
				if topo != nil {
					alerts := scanner.ScanTopology(topo, r.FunctionName)
					output.ScanResults = append(output.ScanResults, alerts...)
				}
			}
		}
	}

	return output
}

func isTestFile(path string) bool {
	base := filepath.Base(path)
	return len(base) >= 8 && base[len(base)-8:] == "_test.go"
}

// Performs a semantic diff between two Go files using the Zipper algorithm.
// Uses topology based matching to detect renamed/obfuscated functions.
// SYNERGY: Risk-Aware Diffs - calculates structural risk scores for changes.
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

	// Use topology matching instead of name-only matching
	// Threshold of 0.6 means functions must be 60%+ structurally similar
	const topologyThreshold = 0.6
	matched, addedFuncs, removedFuncs := semanticfw.MatchFunctionsByTopology(
		oldResults, newResults, topologyThreshold,
	)

	// Compute diffs for each matched pair
	var functionDiffs []FunctionDiff
	var topologyMatches []TopologyMatchInfo
	preserved, modified, renamed, highRisk := 0, 0, 0, 0

	for _, m := range matched {
		oldShort := shortFunctionName(m.OldResult.FunctionName)
		newShort := shortFunctionName(m.NewResult.FunctionName)

		diff := compareFunctions(oldShort, m.OldResult, m.NewResult)

		// If matched by topology (not name), update the diff to reflect renaming
		if !m.ByName {
			diff.Function = fmt.Sprintf("%s → %s", oldShort, newShort)
			renamed++
		}

		// SYNERGY: Risk-Aware Diffs - calculate topology delta and risk score
		if diff.Status == "modified" && m.OldTopology != nil && m.NewTopology != nil {
			delta, riskScore := calculateTopologyDelta(m.OldTopology, m.NewTopology)
			diff.TopologyDelta = delta
			diff.RiskScore = riskScore
			if riskScore >= 10 {
				highRisk++
			}
		}

		functionDiffs = append(functionDiffs, diff)
		if diff.Status == "preserved" {
			preserved++
		} else {
			modified++
		}

		// Record topology match info
		oldTopoStr := ""
		newTopoStr := ""
		if m.OldTopology != nil {
			oldTopoStr = semanticfw.TopologyFingerprint(m.OldTopology)
		}
		if m.NewTopology != nil {
			newTopoStr = semanticfw.TopologyFingerprint(m.NewTopology)
		}

		topologyMatches = append(topologyMatches, TopologyMatchInfo{
			OldFunction:   oldShort,
			NewFunction:   newShort,
			Similarity:    m.Similarity,
			MatchedByName: m.ByName,
			OldTopology:   oldTopoStr,
			NewTopology:   newTopoStr,
		})
	}

	// Add truly new functions (high risk by default - new code paths)
	for _, r := range addedFuncs {
		functionDiffs = append(functionDiffs, FunctionDiff{
			Function:       shortFunctionName(r.FunctionName),
			Status:         "added",
			NewFingerprint: r.Fingerprint,
			RiskScore:      5, // New functions get moderate base risk
		})
	}

	// Add truly removed functions
	for _, r := range removedFuncs {
		functionDiffs = append(functionDiffs, FunctionDiff{
			Function:       shortFunctionName(r.FunctionName),
			Status:         "removed",
			OldFingerprint: r.Fingerprint,
		})
	}

	added := len(addedFuncs)
	removed := len(removedFuncs)

	// Calculate semantic match percentage (based on matched functions)
	total := len(matched) + added + removed
	matchPct := 0.0
	topoMatchPct := 0.0
	if total > 0 {
		matchPct = float64(preserved) / float64(total) * 100.0
	}
	if len(matched) > 0 {
		topoMatchPct = float64(len(matched)) / float64(total) * 100.0
	}

	output := DiffOutput{
		OldFile: oldFile,
		NewFile: newFile,
		Summary: DiffSummary{
			TotalFunctions:     total,
			Preserved:          preserved,
			Modified:           modified,
			Added:              added,
			Removed:            removed,
			SemanticMatchPct:   matchPct,
			TopologyMatchedPct: topoMatchPct,
			RenamedFunctions:   renamed,
			HighRiskChanges:    highRisk,
		},
		Functions:       functionDiffs,
		TopologyMatches: topologyMatches,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// SYNERGY: Risk-Aware Diffs
// calculateTopologyDelta computes structural changes between function versions.
// Returns a human-readable delta string and a risk score.
// Risk factors: added calls (+5 each), added loops (+10 each), added goroutines (+15).
func calculateTopologyDelta(oldT, newT *semanticfw.FunctionTopology) (string, int) {
	if oldT == nil || newT == nil {
		return "Unknown", 0
	}

	var deltas []string
	riskScore := 0

	// Call count changes (new dependencies are risky)
	callDiff := len(newT.CallSignatures) - len(oldT.CallSignatures)
	if callDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Calls+%d", callDiff))
		riskScore += callDiff * 5 // Each new call adds 5 risk points
	} else if callDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Calls%d", callDiff))
	}

	// Loop count changes (new loops can hide malicious behavior)
	loopDiff := newT.LoopCount - oldT.LoopCount
	if loopDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Loops+%d", loopDiff))
		riskScore += loopDiff * 10 // Each new loop adds 10 risk points
	} else if loopDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Loops%d", loopDiff))
	}

	// Branch count changes
	branchDiff := newT.BranchCount - oldT.BranchCount
	if branchDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Branches+%d", branchDiff))
		riskScore += branchDiff * 2 // Minor risk
	} else if branchDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Branches%d", branchDiff))
	}

	// Goroutine additions (very suspicious)
	if newT.HasGo && !oldT.HasGo {
		deltas = append(deltas, "AddedGoroutine")
		riskScore += 15
	}

	// Defer additions
	if newT.HasDefer && !oldT.HasDefer {
		deltas = append(deltas, "AddedDefer")
		riskScore += 3
	}

	// Panic additions
	if newT.HasPanic && !oldT.HasPanic {
		deltas = append(deltas, "AddedPanic")
		riskScore += 5
	}

	// Entropy increase (possible obfuscation)
	entropyDiff := newT.EntropyScore - oldT.EntropyScore
	if entropyDiff > 1.0 {
		deltas = append(deltas, fmt.Sprintf("Entropy+%.1f", entropyDiff))
		riskScore += int(entropyDiff * 3)
	}

	if len(deltas) == 0 {
		return "NoStructuralChange", 0
	}

	return strings.Join(deltas, ", "), riskScore
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

// shortFunctionName extracts the function name without the full package path.
// For example:
//
//	"github.com/foo/bar.Method" -> "Method"
//	"github.com/foo/bar.(*Type).Method" -> "(*Type).Method"
func shortFunctionName(fullName string) string {
	// Find the last occurrence of "/" to strip the full module path
	lastSlash := strings.LastIndex(fullName, "/")
	name := fullName
	if lastSlash >= 0 {
		name = fullName[lastSlash+1:]
	}

	// Now name is like "pkg.FuncName" or "pkg.(*Type).Method"
	// Find the first dot to strip the package name
	depth := 0
	for i, ch := range name {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case '.':
			if depth == 0 {
				return name[i+1:]
			}
		}
	}
	return name
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

// ================================
// INDEX COMMAND (Lab Phase)
// ================================

// Represents the JSON output for the index command.
type IndexOutput struct {
	Message   string               `json:"message"`
	Signature semanticfw.Signature `json:"signature"`
	Database  string               `json:"database"`
	TotalSigs int                  `json:"total_signatures"`
	Error     string               `json:"error,omitempty"`
}

// Returns true if the path looks like a BoltDB file.
func isBoltDB(path string) bool {
	return strings.HasSuffix(path, ".db") || strings.HasSuffix(path, ".bolt")
}

func runIndex(target, name, severity, category, dbPath string) error {
	// Load the file and extract topologies
	results, err := loadAndFingerprint(target)
	if err != nil {
		return fmt.Errorf("failed to load file: %w", err)
	}

	if len(results) == 0 {
		return fmt.Errorf("no functions found in %s", target)
	}

	var indexed []semanticfw.Signature
	var totalSigs int

	if isBoltDB(dbPath) {
		// Use BoltDB backend
		indexed, totalSigs, err = runIndexBolt(target, results, name, severity, category, dbPath)
	} else {
		// Use legacy JSON backend
		indexed, totalSigs, err = runIndexJSON(target, results, name, severity, category, dbPath)
	}
	if err != nil {
		return err
	}

	// Output results
	output := struct {
		Message   string                 `json:"message"`
		Indexed   []semanticfw.Signature `json:"indexed"`
		Database  string                 `json:"database"`
		TotalSigs int                    `json:"total_signatures"`
		Backend   string                 `json:"backend"`
	}{
		Message:   fmt.Sprintf("Indexed %d functions from %s", len(indexed), target),
		Indexed:   indexed,
		Database:  dbPath,
		TotalSigs: totalSigs,
		Backend:   map[bool]string{true: "boltdb", false: "json"}[isBoltDB(dbPath)],
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runIndexBolt(target string, results []semanticfw.FingerprintResult, name, severity, category, dbPath string) ([]semanticfw.Signature, int, error) {
	scanner, err := semanticfw.NewBoltScanner(dbPath, semanticfw.DefaultBoltScannerOptions())
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open database: %w", err)
	}
	defer scanner.Close()

	existingCount, _ := scanner.CountSignatures()

	var sigs []semanticfw.Signature
	for i, result := range results {
		fn := result.GetSSAFunction()
		if fn == nil {
			continue
		}

		topo := semanticfw.ExtractTopology(fn)
		if topo == nil {
			continue
		}

		funcName := shortFunctionName(result.FunctionName)
		sigName := fmt.Sprintf("%s_%s", name, funcName)
		desc := fmt.Sprintf("Function %s from %s", funcName, filepath.Base(target))

		sig := semanticfw.IndexFunction(topo, sigName, desc, severity, category)
		sig.ID = fmt.Sprintf("SFW-%s-%d", strings.ToUpper(category[:3]), existingCount+i+1)
		sig.Metadata = semanticfw.SignatureMetadata{
			Author:  "sfw-index",
			Created: time.Now().Format("2006-01-02"),
		}

		sigs = append(sigs, sig)
	}

	// Bulk add all signatures in single transaction
	if err := scanner.AddSignatures(sigs); err != nil {
		return nil, 0, fmt.Errorf("failed to add signatures: %w", err)
	}

	finalCount, _ := scanner.CountSignatures()
	return sigs, finalCount, nil
}

func runIndexJSON(target string, results []semanticfw.FingerprintResult, name, severity, category, dbPath string) ([]semanticfw.Signature, int, error) {
	// Load existing database or create new one
	scanner := semanticfw.NewScanner()
	if _, err := os.Stat(dbPath); err == nil {
		if err := scanner.LoadDatabase(dbPath); err != nil {
			return nil, 0, fmt.Errorf("failed to load database: %w", err)
		}
	}

	var indexed []semanticfw.Signature
	for _, result := range results {
		fn := result.GetSSAFunction()
		if fn == nil {
			continue
		}

		topo := semanticfw.ExtractTopology(fn)
		if topo == nil {
			continue
		}

		funcName := shortFunctionName(result.FunctionName)
		sigName := fmt.Sprintf("%s_%s", name, funcName)
		desc := fmt.Sprintf("Function %s from %s", funcName, filepath.Base(target))

		sig := semanticfw.IndexFunction(topo, sigName, desc, severity, category)
		sig.ID = fmt.Sprintf("SFW-%s-%d", strings.ToUpper(category[:3]), len(scanner.GetDatabase().Signatures)+len(indexed)+1)
		sig.Metadata = semanticfw.SignatureMetadata{
			Author:  "sfw-index",
			Created: time.Now().Format("2006-01-02"),
		}

		scanner.AddSignature(sig)
		indexed = append(indexed, sig)
	}

	// Save the updated database
	if err := scanner.SaveDatabase(dbPath); err != nil {
		return nil, 0, fmt.Errorf("failed to save database: %w", err)
	}

	return indexed, len(scanner.GetDatabase().Signatures), nil
}

// ================================
// SCAN COMMAND (Hunter Phase)
// ================================

// Configures the scan operation.
type ScanOptions struct {
	DBPath    string
	Threshold float64
	ExactOnly bool
	ScanDeps  bool
	DepsDepth string // "direct" or "transitive"
}

// Represents the JSON output for the scan command.
type ScanOutput struct {
	Target       string                  `json:"target"`
	Database     string                  `json:"database"`
	Backend      string                  `json:"backend"`
	Threshold    float64                 `json:"threshold"`
	TotalScanned int                     `json:"total_functions_scanned"`
	DepsScanned  int                     `json:"dependencies_scanned,omitempty"`
	Alerts       []semanticfw.ScanResult `json:"alerts"`
	Summary      ScanSummary             `json:"summary"`
	ScannedDeps  []string                `json:"scanned_dependencies,omitempty"`
	Error        string                  `json:"error,omitempty"`
}

// Provides aggregate statistics for the scan.
type ScanSummary struct {
	CriticalAlerts int `json:"critical"`
	HighAlerts     int `json:"high"`
	MediumAlerts   int `json:"medium"`
	LowAlerts      int `json:"low"`
	TotalAlerts    int `json:"total_alerts"`
}

func runScan(target string, opts ScanOptions) error {
	// Determine if target is file or directory
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

	var allAlerts []semanticfw.ScanResult
	totalFunctions := 0
	depsScanned := 0
	var scannedDeps []string
	backend := "json"

	if isBoltDB(opts.DBPath) {
		backend = "boltdb"
		allAlerts, totalFunctions, err = runScanBolt(files, opts.DBPath, opts.Threshold, opts.ExactOnly)
	} else {
		allAlerts, totalFunctions, err = runScanJSON(files, opts.DBPath, opts.Threshold)
	}
	if err != nil {
		return err
	}

	// Scan dependencies if requested
	if opts.ScanDeps {
		depAlerts, depFuncs, deps, depErr := runScanDeps(target, opts)
		if depErr != nil {
			// Log warning but don't fail - deps scanning is best effort
			fmt.Fprintf(os.Stderr, "warning: dependency scan incomplete: %v\n", depErr)
		}
		allAlerts = append(allAlerts, depAlerts...)
		depsScanned = depFuncs
		scannedDeps = deps
	}

	// Build summary
	summary := ScanSummary{TotalAlerts: len(allAlerts)}
	for _, alert := range allAlerts {
		switch alert.Severity {
		case "CRITICAL":
			summary.CriticalAlerts++
		case "HIGH":
			summary.HighAlerts++
		case "MEDIUM":
			summary.MediumAlerts++
		case "LOW":
			summary.LowAlerts++
		}
	}

	output := ScanOutput{
		Target:       target,
		Database:     opts.DBPath,
		Backend:      backend,
		Threshold:    opts.Threshold,
		TotalScanned: totalFunctions + depsScanned,
		DepsScanned:  depsScanned,
		Alerts:       allAlerts,
		Summary:      summary,
		ScannedDeps:  scannedDeps,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runScanBolt(files []string, dbPath string, threshold float64, exactOnly bool) ([]semanticfw.ScanResult, int, error) {
	opts := semanticfw.DefaultBoltScannerOptions()
	opts.MatchThreshold = threshold
	opts.ReadOnly = true // Read-only for scanning

	scanner, err := semanticfw.NewBoltScanner(dbPath, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open database: %w", err)
	}
	defer scanner.Close()

	var allAlerts []semanticfw.ScanResult
	totalFunctions := 0

	for _, file := range files {
		results, err := loadAndFingerprint(file)
		if err != nil {
			continue // Skip files that fail to load
		}

		for _, result := range results {
			totalFunctions++
			fn := result.GetSSAFunction()
			if fn == nil {
				continue
			}

			topo := semanticfw.ExtractTopology(fn)
			if topo == nil {
				continue
			}

			funcName := shortFunctionName(result.FunctionName)

			if exactOnly {
				// O(1) exact match only - fastest
				if alert := scanner.ScanTopologyExact(topo, funcName); alert != nil {
					allAlerts = append(allAlerts, *alert)
				}
			} else {
				// Full scan: O(1) exact + O(M) fuzzy
				alerts := scanner.ScanTopology(topo, funcName)
				allAlerts = append(allAlerts, alerts...)
			}
		}
	}

	return allAlerts, totalFunctions, nil
}

func runScanJSON(files []string, dbPath string, threshold float64) ([]semanticfw.ScanResult, int, error) {
	scanner := semanticfw.NewScanner()
	if err := scanner.LoadDatabase(dbPath); err != nil {
		return nil, 0, fmt.Errorf("failed to load signature database: %w", err)
	}
	scanner.SetThreshold(threshold)

	var allAlerts []semanticfw.ScanResult
	totalFunctions := 0

	for _, file := range files {
		results, err := loadAndFingerprint(file)
		if err != nil {
			continue // Skip files that fail to load
		}

		for _, result := range results {
			totalFunctions++
			fn := result.GetSSAFunction()
			if fn == nil {
				continue
			}

			topo := semanticfw.ExtractTopology(fn)
			if topo == nil {
				continue
			}

			funcName := shortFunctionName(result.FunctionName)
			alerts := scanner.ScanTopology(topo, funcName)
			allAlerts = append(allAlerts, alerts...)
		}
	}

	return allAlerts, totalFunctions, nil
}

// runScanDeps scans imported dependencies for malware signatures.
// REMEDIATION: Dependency Memory Bomb Fix
// Uses micro-batching with explicit GC to prevent OOM on large dependency graphs.
func runScanDeps(target string, opts ScanOptions) ([]semanticfw.ScanResult, int, []string, error) {
	// Load packages with dependencies
	pkgs, err := loadPackagesWithDeps(target, opts.DepsDepth == "transitive")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to load dependencies: %w", err)
	}

	// Collect unique dependency packages (excluding stdlib)
	depPkgs := make(map[string]*packages.Package)
	for _, pkg := range pkgs {
		collectDependencies(pkg, depPkgs, opts.DepsDepth == "transitive", make(map[string]bool))
	}

	if len(depPkgs) == 0 {
		return nil, 0, nil, nil
	}

	// Convert to slice for batch processing
	var depSlice []*packages.Package
	for _, pkg := range depPkgs {
		depSlice = append(depSlice, pkg)
	}

	var allAlerts []semanticfw.ScanResult
	totalFunctions := 0
	var scannedDeps []string

	// REMEDIATION: Micro-Batching to prevent OOM
	// Process dependencies in batches, discarding SSA context after each batch
	const batchSize = 50
	for batchStart := 0; batchStart < len(depSlice); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(depSlice) {
			batchEnd = len(depSlice)
		}
		batch := depSlice[batchStart:batchEnd]

		// Build SSA for just this batch
		prog, _ := ssautil.AllPackages(batch, ssa.InstantiateGenerics)
		if prog == nil {
			continue
		}
		prog.Build()

		// Open scanner for this batch (reuse across batch for efficiency)
		var boltScanner *semanticfw.BoltScanner
		var jsonScanner *semanticfw.Scanner

		if isBoltDB(opts.DBPath) {
			scanOpts := semanticfw.DefaultBoltScannerOptions()
			scanOpts.MatchThreshold = opts.Threshold
			scanOpts.ReadOnly = true
			boltScanner, err = semanticfw.NewBoltScanner(opts.DBPath, scanOpts)
			if err != nil {
				continue // Skip batch on DB error
			}
		} else {
			jsonScanner = semanticfw.NewScanner()
			if err := jsonScanner.LoadDatabase(opts.DBPath); err != nil {
				continue // Skip batch on DB error
			}
			jsonScanner.SetThreshold(opts.Threshold)
		}

		// Scan each package in the batch
		for _, pkg := range batch {
			pkgPath := pkg.PkgPath
			scannedDeps = append(scannedDeps, pkgPath)

			ssaPkg := prog.Package(pkg.Types)
			if ssaPkg == nil {
				continue
			}

			// Scan all functions in the dependency
			for _, member := range ssaPkg.Members {
				switch m := member.(type) {
				case *ssa.Function:
					if m == nil || len(m.Blocks) == 0 {
						continue
					}
					alerts := scanFunction(m, pkgPath, boltScanner, jsonScanner, opts.ExactOnly)
					allAlerts = append(allAlerts, alerts...)
					totalFunctions++

				case *ssa.Type:
					// Scan methods on types
					if named, ok := m.Type().(*types.Named); ok {
						for i := 0; i < named.NumMethods(); i++ {
							method := named.Method(i)
							fn := prog.FuncValue(method)
							if fn == nil || len(fn.Blocks) == 0 {
								continue
							}
							alerts := scanFunction(fn, pkgPath, boltScanner, jsonScanner, opts.ExactOnly)
							allAlerts = append(allAlerts, alerts...)
							totalFunctions++
						}
					}
				}
			}
		}

		// Close scanner for this batch
		if boltScanner != nil {
			boltScanner.Close()
		}

		// REMEDIATION: Explicit cleanup to prevent Memory Bomb
		// Discard SSA program and force garbage collection between batches
		prog = nil
		runtime.GC()
	}

	sort.Strings(scannedDeps)
	return allAlerts, totalFunctions, scannedDeps, nil
}

// scanFunction scans a single SSA function against the signature database.
func scanFunction(fn *ssa.Function, pkgPath string, boltScanner *semanticfw.BoltScanner, jsonScanner *semanticfw.Scanner, exactOnly bool) []semanticfw.ScanResult {
	topo := semanticfw.ExtractTopology(fn)
	if topo == nil {
		return nil
	}

	funcName := fmt.Sprintf("%s.%s", pkgPath, fn.Name())

	if boltScanner != nil {
		if exactOnly {
			if alert := boltScanner.ScanTopologyExact(topo, funcName); alert != nil {
				return []semanticfw.ScanResult{*alert}
			}
			return nil
		}
		return boltScanner.ScanTopology(topo, funcName)
	}

	if jsonScanner != nil {
		return jsonScanner.ScanTopology(topo, funcName)
	}

	return nil
}

// loadPackagesWithDeps loads Go packages with their dependencies.
func loadPackagesWithDeps(target string, transitive bool) ([]*packages.Package, error) {
	mode := packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	if transitive {
		mode |= packages.NeedDeps
	}

	cfg := &packages.Config{
		Mode:  mode,
		Dir:   filepath.Dir(target),
		Tests: false,
	}

	// Determine pattern
	pattern := "./..."
	info, err := os.Stat(target)
	if err == nil && !info.IsDir() {
		pattern = "file=" + target
	}

	return packages.Load(cfg, pattern)
}

// collectDependencies recursively collects dependency packages.
func collectDependencies(pkg *packages.Package, deps map[string]*packages.Package, transitive bool, visited map[string]bool) {
	if pkg == nil || visited[pkg.PkgPath] {
		return
	}
	visited[pkg.PkgPath] = true

	for importPath, importPkg := range pkg.Imports {
		// Skip stdlib packages (no dot in path typically means stdlib)
		if !strings.Contains(importPath, ".") {
			continue
		}
		// Skip already collected
		if _, ok := deps[importPath]; ok {
			continue
		}

		deps[importPath] = importPkg

		if transitive {
			collectDependencies(importPkg, deps, transitive, visited)
		}
	}
}

// ================================
// MIGRATE COMMAND
// ================================

func runMigrate(fromPath, toPath string) error {
	// Create new BoltDB scanner
	scanner, err := semanticfw.NewBoltScanner(toPath, semanticfw.DefaultBoltScannerOptions())
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	defer scanner.Close()

	// Migrate from JSON
	count, err := scanner.MigrateFromJSON(fromPath)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	output := struct {
		Message string `json:"message"`
		Source  string `json:"source"`
		Dest    string `json:"destination"`
		Count   int    `json:"signatures_migrated"`
	}{
		Message: fmt.Sprintf("Successfully migrated %d signatures", count),
		Source:  fromPath,
		Dest:    toPath,
		Count:   count,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// ================================
// STATS COMMAND
// ================================

func runStats(dbPath string) error {
	if !isBoltDB(dbPath) {
		// For JSON, just load and count
		scanner := semanticfw.NewScanner()
		if err := scanner.LoadDatabase(dbPath); err != nil {
			return fmt.Errorf("failed to load database: %w", err)
		}
		db := scanner.GetDatabase()

		output := struct {
			Database       string `json:"database"`
			Backend        string `json:"backend"`
			Version        string `json:"version"`
			SignatureCount int    `json:"signature_count"`
		}{
			Database:       dbPath,
			Backend:        "json",
			Version:        db.Version,
			SignatureCount: len(db.Signatures),
		}

		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	// BoltDB stats
	opts := semanticfw.DefaultBoltScannerOptions()
	opts.ReadOnly = true

	scanner, err := semanticfw.NewBoltScanner(dbPath, opts)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer scanner.Close()

	stats, err := scanner.Stats()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	// Get file size
	fileInfo, _ := os.Stat(dbPath)
	var fileSize int64
	if fileInfo != nil {
		fileSize = fileInfo.Size()
	}

	output := struct {
		Database         string `json:"database"`
		Backend          string `json:"backend"`
		SignatureCount   int    `json:"signature_count"`
		TopoIndexCount   int    `json:"topology_index_count"`
		EntropyIndexSize int64  `json:"entropy_index_bytes"`
		FileSizeBytes    int64  `json:"file_size_bytes"`
		FileSizeHuman    string `json:"file_size_human"`
	}{
		Database:         dbPath,
		Backend:          "boltdb",
		SignatureCount:   stats.SignatureCount,
		TopoIndexCount:   stats.TopoIndexCount,
		EntropyIndexSize: stats.EntropyIndexSize,
		FileSizeBytes:    fileSize,
		FileSizeHuman:    humanizeBytes(fileSize),
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func humanizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// resolveDBPath attempts to find the signature database in several standard locations
// if a specific path is not provided.
// It checks:
// 1. SFW_DB_PATH environment variable
// 2. Current directory (./signatures.db)
// 3. User home directory (~/.sfw/signatures.db)
// 4. System share directory (/usr/local/share/sfw/signatures.db)
func resolveDBPath(path string) string {
	if path != "" {
		return path
	}

	// 1. Environment variable
	if env := os.Getenv("SFW_DB_PATH"); env != "" {
		return env
	}

	// 2. Standard locations to check
	candidates := []string{
		"./signatures.db",
	}

	// User home directory
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".sfw", "signatures.db"))
	}

	// System locations
	candidates = append(candidates,
		"/usr/local/share/sfw/signatures.db",
		"/var/lib/sfw/signatures.db",
	)

	// Check if any candidate exists
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	// Fallback to local if nothing found (will likely fail to open, but helpful error)
	return "./signatures.db"
}
