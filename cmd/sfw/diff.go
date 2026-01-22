// -- ./cmd/sfw/diff.go --
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

// computeDiff orchestrates the comparison between two Go source files.
// It handles environment isolation to prevent loader collisions, computes
// semantic fingerprints, and performs topology risk analysis to generate
// a comprehensive diff report.
func computeDiff(oldFile, newFile string) (*DiffOutput, error) {
	// -- Helper Execution --

	// processes files in strict isolation.
	// CRITICAL_001_REDECLARATION_CRASH: We must write each file to a unique
	// temporary directory so the Go loader treats them as separate packages.
	// This prevents "redeclared in this block" errors when diffing versions
	// that sit in the same parent directory.
	fingerprintIsolated := func(path string) ([]semanticfw.FingerprintResult, error) {
		if path == "" {
			return []semanticfw.FingerprintResult{}, nil
		}

		// reads content safely while respecting MaxSourceFileSize constraints.
		content, err := readSourceFile(path)
		if err != nil {
			return nil, err
		}

		// creates a unique temp dir for isolation.
		tmpDir, err := os.MkdirTemp("", "sfw-diff-iso-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp isolation dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		// writes file to temp dir with original basename to preserve context hints.
		baseName := filepath.Base(path)
		if baseName == "." || baseName == "/" {
			baseName = "file.go"
		}
		isoPath := filepath.Join(tmpDir, baseName)
		if err := os.WriteFile(isoPath, content, FilePermReadWrite); err != nil {
			return nil, fmt.Errorf("failed to write isolated file: %w", err)
		}

		return semanticfw.FingerprintSource(isoPath, string(content), semanticfw.DefaultLiteralPolicy)
	}

	var oldResults []semanticfw.FingerprintResult
	var err error

	// -- File Ingestion --

	// checks for non existent old file which implies a Creation event.
	if _, statErr := os.Stat(oldFile); os.IsNotExist(statErr) {
		oldResults = []semanticfw.FingerprintResult{}
	} else {
		oldResults, err = fingerprintIsolated(oldFile)
		if err != nil {
			// propagates errors instead of swallowing them unless it is a pure file not found scenario.
			if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") {
				oldResults = []semanticfw.FingerprintResult{}
			} else {
				return nil, fmt.Errorf("failed to process old file: %w", err)
			}
		}
	}

	var newResults []semanticfw.FingerprintResult
	// checks for non existent new file which implies a Deletion event.
	if _, statErr := os.Stat(newFile); os.IsNotExist(statErr) {
		newResults = []semanticfw.FingerprintResult{}
	} else {
		newResults, err = fingerprintIsolated(newFile)
		if err != nil {
			if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") {
				newResults = []semanticfw.FingerprintResult{}
			} else {
				return nil, fmt.Errorf("failed to process new file: %w", err)
			}
		}
	}

	// aligns functions based on their structural topology rather than just name matching.
	matched, addedFuncs, removedFuncs := semanticfw.MatchFunctionsByTopology(
		oldResults, newResults, DefaultTopologyMatchThreshold,
	)

	var functionDiffs []FunctionDiff
	var topologyMatches []TopologyMatchInfo
	preserved, modified, renamed, highRisk := 0, 0, 0, 0

	// -- Diff Analysis --

	for _, m := range matched {
		oldShort := shortFunctionName(m.OldResult.FunctionName)
		newShort := shortFunctionName(m.NewResult.FunctionName)

		// compares fingerprint and body first to determine basic modification status.
		diff := compareFunctions(oldShort, m.OldResult, m.NewResult)

		// -- Topology Risk Analysis --
		// We calculate risk BEFORE checking for renames. If a function was renamed
		// AND modified, we still want to capture that risk data here.
		if diff.Status == StatusModified && m.OldTopology != nil && m.NewTopology != nil {
			delta, riskScore := calculateTopologyDelta(m.OldTopology, m.NewTopology)
			diff.TopologyDelta = delta
			diff.RiskScore = riskScore
			if riskScore >= RiskScoreHigh {
				highRisk++
			}
		}

		// -- Rename Detection --
		// If the topology matcher found a match but the names differ, it is a rename.
		// We override the status here so the final output explicitly says "renamed".
		if !m.ByName {
			diff.Function = fmt.Sprintf("%s → %s", oldShort, newShort)
			diff.Status = StatusRenamed
			renamed++
		}

		functionDiffs = append(functionDiffs, diff)

		// -- Stats Counting --
		// updates counters based on the final status using a tagged switch for clarity.
		// Note: We deliberately exclude "renamed" here because it was incremented above.
		switch diff.Status {
		case StatusPreserved:
			preserved++
		case StatusModified:
			modified++
		}

		oldTopoStr := ""
		if m.OldTopology != nil {
			oldTopoStr = semanticfw.TopologyFingerprint(m.OldTopology)
		}
		newTopoStr := ""
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

	// -- New Vector Analysis --

	// bypasses vulnerability remediation scans to analyze topology of added functions.
	// This detects high risk features (loops, C2 calls) in code that has no history.
	for _, r := range addedFuncs {
		risk := BaseRiskAddedFunc
		delta := TopoDeltaNew

		fn := r.GetSSAFunction()
		if fn != nil {
			topo := semanticfw.ExtractTopology(fn)
			if topo != nil {
				// Passing nil as oldT allows delta calc against empty state.
				d, s := calculateTopologyDelta(nil, topo)
				delta = d
				risk = s
			}
		}

		if risk >= RiskScoreHigh {
			highRisk++
		}

		functionDiffs = append(functionDiffs, FunctionDiff{
			Function:       shortFunctionName(r.FunctionName),
			Status:         StatusAdded,
			NewFingerprint: r.Fingerprint,
			RiskScore:      risk,
			TopologyDelta:  delta,
		})
	}

	for _, r := range removedFuncs {
		functionDiffs = append(functionDiffs, FunctionDiff{
			Function:       shortFunctionName(r.FunctionName),
			Status:         StatusRemoved,
			OldFingerprint: r.Fingerprint,
		})
	}

	// -- Summary Generation --

	added := len(addedFuncs)
	removed := len(removedFuncs)
	total := len(matched) + added + removed
	matchPct := 0.0
	topoMatchPct := 0.0
	if total > 0 {
		matchPct = float64(preserved) / float64(total) * 100.0
	}
	if len(matched) > 0 {
		topoMatchPct = float64(len(matched)) / float64(total) * 100.0
	}

	return &DiffOutput{
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
	}, nil
}

// calculateTopologyDelta computes the structural drift between two function states.
// It assigns a risk score based on heuristics like added concurrency, loops,
// or entropy changes which often indicate complex logic or obfuscation.
func calculateTopologyDelta(oldT, newT *semanticfw.FunctionTopology) (string, int) {
	// assumes no change or error if the new topology is missing.
	if newT == nil {
		return TopoDeltaUnknown, 0
	}
	// handles nil oldT for Added functions by treating it as an empty baseline.
	if oldT == nil {
		oldT = &semanticfw.FunctionTopology{}
	}

	var deltas []string
	riskScore := 0

	callDiff := len(newT.CallSignatures) - len(oldT.CallSignatures)
	if callDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Calls+%d", callDiff))
		riskScore += callDiff * 5
	} else if callDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Calls%d", callDiff))
	}

	loopDiff := newT.LoopCount - oldT.LoopCount
	if loopDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Loops+%d", loopDiff))
		riskScore += loopDiff * 10
	} else if loopDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Loops%d", loopDiff))
	}

	branchDiff := newT.BranchCount - oldT.BranchCount
	if branchDiff > 0 {
		deltas = append(deltas, fmt.Sprintf("Branches+%d", branchDiff))
		riskScore += branchDiff * 2
	} else if branchDiff < 0 {
		deltas = append(deltas, fmt.Sprintf("Branches%d", branchDiff))
	}

	if newT.HasGo && !oldT.HasGo {
		deltas = append(deltas, TopoDeltaGoroutine)
		riskScore += 15
	}

	if newT.HasDefer && !oldT.HasDefer {
		deltas = append(deltas, TopoDeltaDefer)
		riskScore += 3
	}

	if newT.HasPanic && !oldT.HasPanic {
		deltas = append(deltas, TopoDeltaPanic)
		riskScore += 5
	}

	entropyDiff := newT.EntropyScore - oldT.EntropyScore
	if entropyDiff > 1.0 {
		deltas = append(deltas, fmt.Sprintf("Entropy+%.1f", entropyDiff))
		riskScore += int(entropyDiff * 3)
	}

	if len(deltas) == 0 {
		return TopoDeltaNone, 0
	}

	return strings.Join(deltas, ", "), riskScore
}

// compareFunctions performs a tiered comparison of two function states.
// It starts with a cheap fingerprint check and escalates to a full SSA
// zipper traversal if the fingerprints disagree.
func compareFunctions(funcName string, oldResult, newResult semanticfw.FingerprintResult) FunctionDiff {
	diff := FunctionDiff{
		Function:       funcName,
		OldFingerprint: oldResult.Fingerprint,
		NewFingerprint: newResult.Fingerprint,
	}

	if oldResult.Fingerprint == newResult.Fingerprint {
		diff.Status = StatusPreserved
		diff.FingerprintMatch = true
		return diff
	}

	diff.FingerprintMatch = false
	oldFn := oldResult.GetSSAFunction()
	newFn := newResult.GetSSAFunction()

	if oldFn == nil || newFn == nil {
		diff.Status = StatusModified
		return diff
	}

	// computes the deep semantic difference between the two SSA forms.
	zipper, err := semanticfw.NewZipper(oldFn, newFn, semanticfw.DefaultLiteralPolicy)
	if err != nil {
		diff.Status = StatusModified
		return diff
	}

	artifacts, err := zipper.ComputeDiff()
	if err != nil {
		diff.Status = StatusModified
		return diff
	}

	diff.MatchedNodes = artifacts.MatchedNodes
	diff.AddedOps = artifacts.Added
	diff.RemovedOps = artifacts.Removed

	if artifacts.Preserved {
		diff.Status = StatusPreserved
	} else {
		diff.Status = StatusModified
	}

	return diff
}
