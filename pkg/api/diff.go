package api

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
	"golang.org/x/tools/go/ssa"
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
		content, absPath, err := readDiffInput(fsys, path)
		if err != nil || content == nil {
			return []diff.FingerprintResult{}, err
		}
		paths := pathResolver{}
		results, err := diff.FingerprintSourceWhere(absPath, string(content), ir.DefaultLiteralPolicy, false, paths.keepFiles(absPath))
		if err != nil {
			return nil, err
		}
		return inFile(results, absPath, paths), nil
	}

	// Load the two versions at the same time; report the old side's error
	// first when both fail.
	var oldResults, newResults []diff.FingerprintResult
	var oldErr, newErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); oldResults, oldErr = processFile(oldPath) }()
	go func() { defer wg.Done(); newResults, newErr = processFile(newPath) }()
	wg.Wait()
	if oldErr != nil {
		return nil, fmt.Errorf("failed to process old file: %w", oldErr)
	}
	if newErr != nil {
		return nil, fmt.Errorf("failed to process new file: %w", newErr)
	}
	return diffResults(oldPath, newPath, oldResults, newResults, riskProfile{}), nil
}

// diffResults pairs two sets of fingerprinted functions, compares each pair,
// scores the changes and summarizes them. It is the part of a diff that does
// not depend on where the functions came from.
func diffResults(oldPath, newPath string, oldResults, newResults []diff.FingerprintResult, profile riskProfile) *models.DiffOutput {
	matched, addedFuncs, removedFuncs := diff.MatchFunctionsByTopology(
		oldResults, newResults, models.DefaultTopologyMatchThreshold,
	)

	// An empty diff lists no functions as [], not null.
	functionDiffs := []models.FunctionDiff{}
	var topologyMatches []models.TopologyMatchInfo
	preserved, modified, renamed, highRisk := 0, 0, 0, 0

	for _, m := range matched {
		oldShort := ResultName(m.OldResult)
		newShort := ResultName(m.NewResult)

		d := CompareFunctions(oldShort, m.OldResult, m.NewResult)

		if m.OldTopology != nil && m.NewTopology != nil {
			r := assessTopologyDeltaFor(m.OldTopology, m.NewTopology, profile)
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
		} else if oldShort != newShort {
			// Paired as the same function under a different name: a closure
			// whose creation number shifted ("F$1" -> "F$2") or a method whose
			// type parameter was renamed. It keeps its status.
			d.Function = fmt.Sprintf("%s → %s", oldShort, newShort)
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
		if fn := r.GetSSAFunction(); fn != nil {
			if topo := topology.ExtractTopology(fn); topo != nil {
				delta, risk = addedDelta(topo, profile)
			}
		}

		if risk >= models.RiskScoreHigh {
			highRisk++
		}

		functionDiffs = append(functionDiffs, models.FunctionDiff{
			Function:       ResultName(r),
			Status:         models.StatusAdded,
			NewFingerprint: r.Fingerprint,
			RiskScore:      risk,
			TopologyDelta:  delta,
		})
	}

	for _, r := range removedFuncs {
		d := models.FunctionDiff{
			Function:       ResultName(r),
			Status:         models.StatusRemoved,
			OldFingerprint: r.Fingerprint,
		}
		if fn := r.GetSSAFunction(); fn != nil {
			if topo := topology.ExtractTopology(fn); topo != nil {
				d.TopologyDelta, d.RiskScore = removedDelta(topo)
			}
		}
		if d.RiskScore >= models.RiskScoreHigh {
			highRisk++
		}
		functionDiffs = append(functionDiffs, d)
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
	}
}

// CompareFunctions reduces two FingerprintResult values to a
// FunctionDiff. A function is preserved only when its canonical IR is
// unchanged with every literal kept: the default fingerprint masks strings
// and larger integers, so on its own it would report a changed URL, command,
// size limit or permission mode as preserved. Any other function is
// modified; the Zipper only supplies the instruction-level evidence. Its
// alignment is driven by data flow, so it must not decide the status: a
// swapped branch or a call moved out of its guard aligns completely.
func CompareFunctions(funcName string, oldResult, newResult diff.FingerprintResult) models.FunctionDiff {
	d := models.FunctionDiff{
		Function:         funcName,
		OldFingerprint:   oldResult.Fingerprint,
		NewFingerprint:   newResult.Fingerprint,
		FingerprintMatch: oldResult.Fingerprint == newResult.Fingerprint,
	}

	oldFn := oldResult.GetSSAFunction()
	newFn := newResult.GetSSAFunction()

	if d.FingerprintMatch && (oldFn == nil || newFn == nil || literalsUnchanged(oldFn, newFn)) {
		d.Status = models.StatusPreserved
		return d
	}

	if oldFn == nil || newFn == nil {
		d.Status = models.StatusModified
		return d
	}

	zipper, err := diff.NewZipper(oldFn, newFn, ir.KeepAllLiteralsPolicy)
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
	d.Status = models.StatusModified
	return d
}

// literalsUnchanged reports whether two functions canonicalize identically
// with every literal kept.
func literalsUnchanged(oldFn, newFn *ssa.Function) bool {
	return diff.GenerateFingerprint(oldFn, ir.KeepAllLiteralsPolicy, false).Fingerprint ==
		diff.GenerateFingerprint(newFn, ir.KeepAllLiteralsPolicy, false).Fingerprint
}

// inFile keeps the functions declared in the file at path. The loader
// returns every function of the file's package; a diff of one file must not
// report its siblings' changes. Functions without a source file (the
// synthesized package initializer, which runs every file's package-level
// initializers) are kept so a payload in a package-level variable is never
// hidden. Paths are compared cleaned and with symbolic links resolved.
func inFile(results []diff.FingerprintResult, path string, paths pathResolver) []diff.FingerprintResult {
	want := paths.resolve(path)
	kept := results[:0:0]
	for _, r := range results {
		if r.Filename == "" || paths.resolve(r.Filename) == want {
			kept = append(kept, r)
		}
	}
	return kept
}

// pathResolver cleans a path and resolves its symbolic links once per
// distinct path: every function of a file names the same path, and a batch
// filters one package's functions for each of its files.
type pathResolver map[string]string

// keepFiles returns the keep function of diff.FingerprintPackagesWhere
// that accepts the files at paths, compared as inFile compares them, so
// only the functions inFile can keep are fingerprinted.
func (r pathResolver) keepFiles(paths ...string) func(filename string) bool {
	want := make(map[string]bool, len(paths))
	for _, p := range paths {
		want[r.resolve(p)] = true
	}
	return func(filename string) bool { return want[r.resolve(filename)] }
}

func (r pathResolver) resolve(path string) string {
	resolved, ok := r[path]
	if !ok {
		resolved = filepath.Clean(path)
		if real, err := filepath.EvalSymlinks(resolved); err == nil {
			resolved = real
		}
		r[path] = resolved
	}
	return resolved
}
