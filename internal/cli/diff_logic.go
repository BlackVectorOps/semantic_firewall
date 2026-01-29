// -- internal/cli/diff_logic.go --
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/models"
)

// -- Public API --

func RunDiff(oldFile, newFile string, noSandbox bool) error {
	cleanOld := filepath.Clean(oldFile)
	cleanNew := filepath.Clean(newFile)
	sb := RealSandboxer{}
	fsys := RealFileSystem{}

	if !noSandbox && !sb.IsSandboxed() {
		args := []string{cleanOld, cleanNew}
		return SandboxExec(sb, os.Stdout, os.Stderr, "diff", args, cleanOld, cleanNew)
	}

	return RunDiffLogic(fsys, cleanOld, cleanNew)
}

// -- Core Logic --

func RunDiffLogic(fsys FileSystem, oldFile, newFile string) error {
	diffOutput, err := ComputeDiff(fsys, oldFile, newFile)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(diffOutput)
}

func ComputeDiff(fsys FileSystem, oldFile, newFile string) (*models.DiffOutput, error) {
	processFile := func(path string) ([]diff.FingerprintResult, error) {
		if path == "" {
			return []diff.FingerprintResult{}, nil
		}
		info, statErr := fsys.Stat(path)
		if os.IsNotExist(statErr) {
			return []diff.FingerprintResult{}, nil
		}
		if info.Size() > MaxSourceFileSize {
			return nil, fmt.Errorf("file %s exceeds maximum analysis size of %d bytes", path, MaxSourceFileSize)
		}
		content, err := fsys.ReadFile(path)
		if err != nil {
			return nil, err
		}
		absPath, err := fsys.Abs(path)
		if err != nil {
			absPath = path
		}
		return diff.FingerprintSource(absPath, string(content), ir.DefaultLiteralPolicy)
	}

	oldResults, err := processFile(oldFile)
	if err != nil {
		return nil, fmt.Errorf("failed to process old file: %w", err)
	}

	newResults, err := processFile(newFile)
	if err != nil {
		return nil, fmt.Errorf("failed to process new file: %w", err)
	}

	matched, addedFuncs, removedFuncs := diff.MatchFunctionsByTopology(
		oldResults, newResults, models.DefaultTopologyMatchThreshold,
	)

	var functionDiffs []models.FunctionDiff
	var topologyMatches []models.TopologyMatchInfo
	preserved, modified, renamed, highRisk := 0, 0, 0, 0

	for _, m := range matched {
		oldShort := ShortFunctionName(m.OldResult.FunctionName)
		newShort := ShortFunctionName(m.NewResult.FunctionName)

		d := CompareFunctions(oldShort, m.OldResult, m.NewResult)

		if d.Status == models.StatusModified && m.OldTopology != nil && m.NewTopology != nil {
			delta, riskScore := CalculateTopologyDelta(m.OldTopology, m.NewTopology)
			d.TopologyDelta = delta
			d.RiskScore = riskScore
			if riskScore >= models.RiskScoreHigh {
				highRisk++
			}
		}

		if !m.ByName {
			d.Function = fmt.Sprintf("%s → %s", oldShort, newShort)
			d.Status = models.StatusRenamed
			renamed++
		}

		functionDiffs = append(functionDiffs, d)

		if d.Status == models.StatusPreserved {
			preserved++
		} else {
			modified++
		}

		oldTopoStr := ""
		if m.OldTopology != nil {
			oldTopoStr = topology.TopologyFingerprint(m.OldTopology)
		}
		newTopoStr := ""
		if m.NewTopology != nil {
			newTopoStr = topology.TopologyFingerprint(m.NewTopology)
		}

		topologyMatches = append(topologyMatches, models.TopologyMatchInfo{
			OldFunction:   oldShort,
			NewFunction:   newShort,
			Similarity:    m.Similarity,
			MatchedByName: m.ByName,
			OldTopology:   oldTopoStr,
			NewTopology:   newTopoStr,
		})
	}

	for _, r := range addedFuncs {
		risk := models.BaseRiskAddedFunc
		delta := models.TopoDeltaNew

		fn := r.GetSSAFunction()
		if fn != nil {
			topo := topology.ExtractTopology(fn)
			if topo != nil {
				d, s := CalculateTopologyDelta(nil, topo)
				delta = d
				risk += s
			}
		}

		if risk >= models.RiskScoreHigh {
			highRisk++
		}

		functionDiffs = append(functionDiffs, models.FunctionDiff{
			Function:       ShortFunctionName(r.FunctionName),
			Status:         models.StatusAdded,
			NewFingerprint: r.Fingerprint,
			RiskScore:      risk,
			TopologyDelta:  delta,
		})
	}

	for _, r := range removedFuncs {
		functionDiffs = append(functionDiffs, models.FunctionDiff{
			Function:       ShortFunctionName(r.FunctionName),
			Status:         models.StatusRemoved,
			OldFingerprint: r.Fingerprint,
		})
	}

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

	return &models.DiffOutput{
		OldFile: oldFile,
		NewFile: newFile,
		Summary: models.DiffSummary{
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

func CalculateTopologyDelta(oldT, newT *topology.FunctionTopology) (string, int) {
	if newT == nil {
		return models.TopoDeltaUnknown, 0
	}
	if oldT == nil {
		oldT = &topology.FunctionTopology{}
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
		deltas = append(deltas, models.TopoDeltaGoroutine)
		riskScore += 15
	}

	if newT.HasDefer && !oldT.HasDefer {
		deltas = append(deltas, models.TopoDeltaDefer)
		riskScore += 3
	}

	if newT.HasPanic && !oldT.HasPanic {
		deltas = append(deltas, models.TopoDeltaPanic)
		riskScore += 5
	}

	entropyDiff := newT.EntropyScore - oldT.EntropyScore
	if entropyDiff > 1.0 {
		deltas = append(deltas, fmt.Sprintf("Entropy+%.1f", entropyDiff))
		riskScore += int(entropyDiff * 3)
	}

	if len(deltas) == 0 {
		return models.TopoDeltaNone, 0
	}

	return strings.Join(deltas, ", "), riskScore
}

func CompareFunctions(funcName string, oldResult, newResult diff.FingerprintResult) models.FunctionDiff {
	d := models.FunctionDiff{
		Function:       funcName,
		OldFingerprint: oldResult.Fingerprint,
		NewFingerprint: newResult.Fingerprint,
	}

	if oldResult.Fingerprint == newResult.Fingerprint {
		d.Status = models.StatusPreserved
		d.FingerprintMatch = true
		return d
	}

	d.FingerprintMatch = false
	oldFn := oldResult.GetSSAFunction()
	newFn := newResult.GetSSAFunction()

	if oldFn == nil || newFn == nil {
		d.Status = models.StatusModified
		return d
	}

	zipper, err := diff.NewZipper(oldFn, newFn, ir.DefaultLiteralPolicy)
	if err != nil {
		d.Status = models.StatusModified
		return d
	}

	artifacts, err := zipper.ComputeDiff()
	if err != nil {
		d.Status = models.StatusModified
		return d
	}

	d.MatchedNodes = artifacts.MatchedNodes
	d.AddedOps = artifacts.Added
	d.RemovedOps = artifacts.Removed

	if artifacts.Preserved {
		d.Status = models.StatusPreserved
	} else {
		d.Status = models.StatusModified
	}

	return d
}
