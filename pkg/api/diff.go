package api

import (
	"fmt"
	"os"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
)

// Diff is the convenience entry point: it computes a semantic diff
// between two on-disk Go source files using the real filesystem.
// Either path may be empty or non-existent to represent an added or
// removed file.
func Diff(oldPath, newPath string) (*models.DiffOutput, error) {
	return DiffWithFS(RealFileSystem{}, oldPath, newPath)
}

// DiffWithFS performs a semantic diff against the supplied FileSystem
// so tests can drive the pipeline without touching disk. Behaviour is
// identical to Diff otherwise.
func DiffWithFS(fsys FileSystem, oldPath, newPath string) (*models.DiffOutput, error) {
	processFile := func(path string) ([]diff.FingerprintResult, error) {
		if path == "" {
			return []diff.FingerprintResult{}, nil
		}
		info, statErr := fsys.Stat(path)
		if statErr != nil {
			// A missing file is a valid "no functions" case (added/removed
			// file). Any other stat error must surface so we never
			// dereference the nil FileInfo below.
			if os.IsNotExist(statErr) {
				return []diff.FingerprintResult{}, nil
			}
			return nil, fmt.Errorf("failed to stat %s: %w", path, statErr)
		}
		if info.Size() > models.MaxSourceFileSize {
			return nil, fmt.Errorf("file %s exceeds maximum analysis size of %d bytes", path, models.MaxSourceFileSize)
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

	oldResults, err := processFile(oldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to process old file: %w", err)
	}
	newResults, err := processFile(newPath)
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

		if m.OldTopology != nil && m.NewTopology != nil {
			r := assessTopologyDelta(m.OldTopology, m.NewTopology)
			// The canonical IR names callees without their package, so a
			// fingerprint match can still hide a swapped-in capability
			// (a same-named, same-signature function from another package).
			if d.Status == models.StatusPreserved && len(r.newCapabilities) > 0 {
				d.Status = models.StatusModified
			}
			if d.Status == models.StatusModified {
				d.TopologyDelta = r.delta()
				d.RiskScore = r.score(0)
				if d.RiskScore >= models.RiskScoreHigh {
					highRisk++
				}
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
				a := assessTopologyDelta(nil, topo)
				if len(a.labels) > 0 {
					delta = a.delta()
				}
				risk = a.score(models.BaseRiskAddedFunc)
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
		OldFile: oldPath,
		NewFile: newPath,
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

// CompareFunctions reduces two FingerprintResult values to a
// FunctionDiff. When the canonical IR fingerprints match the function
// is preserved verbatim; otherwise the Zipper algorithm computes the
// structural delta, falling back to "modified" if SSA reconstruction
// fails.
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
