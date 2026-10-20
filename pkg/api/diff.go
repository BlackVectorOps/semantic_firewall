package api

import (
	"fmt"
	"path/filepath"
	"slices"
	"sync"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/diff"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
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
	processFile := func(path string) FileFingerprints {
		content, absPath, err := readDiffInput(fsys, path)
		if err != nil || content == nil {
			return FileFingerprints{Results: []diff.FingerprintResult{}, Err: err, absent: err == nil}
		}
		paths := pathResolver{}
		results, err := diff.FingerprintSourceWhere(absPath, string(content), ir.DefaultLiteralPolicy, false, paths.keepFiles(absPath))
		if err != nil {
			return FileFingerprints{Err: err}
		}
		return FileFingerprints{Results: inFile(results, absPath, paths), source: parseUnanalyzed(absPath, content)}
	}

	// Load the two versions at the same time; report the old side's error
	// first when both fail.
	var oldSide, newSide FileFingerprints
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); oldSide = processFile(oldPath) }()
	go func() { defer wg.Done(); newSide = processFile(newPath) }()
	wg.Wait()
	if oldSide.Err != nil {
		return nil, fmt.Errorf("failed to process old file: %w", oldSide.Err)
	}
	if newSide.Err != nil {
		return nil, fmt.Errorf("failed to process new file: %w", newSide.Err)
	}
	return diffSides(oldPath, newPath, oldSide, newSide), nil
}

// diffSides is diffResults for the two versions of one file, except when
// the file left a default build it was in, or entered the default builds
// from none (see diff.DefaultBuilds): a //go:build line, a GOOS or GOARCH
// name suffix or an import "C" changed which builds compile it. Its
// functions then left or entered those builds whatever their code, so the
// old version is diffed as removed and the new one as added (when some
// build still compiles it), and the result carries a "build" change in
// Unanalyzed. Otherwise the versions are compared as usual.
func diffSides(oldPath, newPath string, oldSide, newSide FileFingerprints) *models.DiffOutput {
	if oldSide.absent || newSide.absent {
		return diffResults(oldPath, newPath, oldSide, newSide, riskProfile{})
	}
	oldBuilds, newBuilds := oldSide.source.builds, newSide.source.builds
	left := false
	for _, b := range oldBuilds {
		left = left || !slices.Contains(newBuilds, b)
	}
	entered := len(oldBuilds) == 0 && len(newBuilds) > 0
	if !left && !entered {
		return diffResults(oldPath, newPath, oldSide, newSide, riskProfile{})
	}

	absent := FileFingerprints{Results: []diff.FingerprintResult{}, absent: true}
	var parts []*models.DiffOutput
	change := "added"
	if left {
		parts = append(parts, diffResults(oldPath, newPath, oldSide, absent, riskProfile{}))
		change = "removed"
	}
	if len(newBuilds) > 0 {
		parts = append(parts, diffResults(oldPath, newPath, absent, newSide, riskProfile{}))
		if left {
			change = "modified"
		}
	}
	out := &models.DiffOutput{OldFile: oldPath, NewFile: newPath, Functions: []models.FunctionDiff{}}
	for _, p := range parts {
		out.Functions = append(out.Functions, p.Functions...)
		out.Unanalyzed = append(out.Unanalyzed, p.Unanalyzed...)
		out.Summary.TotalFunctions += p.Summary.TotalFunctions
		out.Summary.Added += p.Summary.Added
		out.Summary.Removed += p.Summary.Removed
		out.Summary.HighRiskChanges += p.Summary.HighRiskChanges
	}
	out.Unanalyzed = append(out.Unanalyzed, models.FileChange{File: newPath, Kind: "build", Change: change})
	return out
}

// diffResults pairs the fingerprinted functions of two versions of a file,
// compares each pair, scores the changes and summarizes them, with the
// file's body-less functions and linkname directives (see diffBodyless and
// diffLinknames). It is the part of a diff that does not depend on where
// the functions came from.
func diffResults(oldPath, newPath string, oldSide, newSide FileFingerprints, profile riskProfile) *models.DiffOutput {
	// A deleted file's synthesized package initializer runs every file's
	// package-level initializers, and the package's other files still do;
	// reporting it removed would charge the deletion with their checks.
	// The deleted file's own init functions have a file and stay.
	if newSide.absent && !oldSide.absent {
		oldSide.Results = withoutPackageInit(oldSide.Results)
	}
	matched, addedFuncs, removedFuncs := diff.MatchFunctionsByTopology(
		oldSide.Results, newSide.Results, models.DefaultTopologyMatchThreshold,
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

	addedTopos := make(map[*ssa.Function]*topology.FunctionTopology, len(addedFuncs))
	for _, r := range addedFuncs {
		if fn := r.GetSSAFunction(); fn != nil {
			addedTopos[fn] = topology.ExtractTopology(fn)
		}
	}
	// A dependency's moves are left to the reach analysis of deps diff.
	var moved map[*ssa.Function]map[string][]string
	if profile.ownModule == "" {
		moved = movedCapabilities(matched, addedTopos)
	}

	for _, r := range addedFuncs {
		risk := models.BaseRiskAddedFunc
		delta := models.TopoDeltaNew
		if fn := r.GetSSAFunction(); fn != nil {
			if topo := addedTopos[fn]; topo != nil {
				if m := moved[fn]; len(m) > 0 {
					delta, risk = movedDelta(topo, m, profile)
				} else {
					delta, risk = addedDelta(topo, profile)
				}
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

	pairs, added, removed := len(matched), len(addedFuncs), len(removedFuncs)
	for _, d := range diffBodyless(oldSide.source.bodyless, newSide.source.bodyless) {
		switch d.Status {
		case models.StatusPreserved:
			preserved++
			pairs++
		case models.StatusModified:
			modified++
			pairs++
		case models.StatusAdded:
			added++
		case models.StatusRemoved:
			removed++
		}
		if d.RiskScore >= models.RiskScoreHigh {
			highRisk++
		}
		functionDiffs = append(functionDiffs, d)
	}
	// Directives are not functions: they count as high-risk changes only.
	unanalyzed := diffLinknames(oldPath, newPath, oldSide.source.linknames, newSide.source.linknames)
	for _, fc := range unanalyzed {
		if fc.RiskScore >= models.RiskScoreHigh {
			highRisk++
		}
	}

	total := pairs + added + removed
	matchPct := 0.0
	topoMatchPct := 0.0
	if total > 0 {
		matchPct = float64(preserved) / float64(total) * 100.0
	}
	if pairs > 0 {
		topoMatchPct = float64(pairs) / float64(total) * 100.0
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
		Unanalyzed:      unanalyzed,
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

	// The Zipper's evidence needs both SSA functions (NewZipper refuses a
	// nil one, as results built outside a load have).
	d.Status = models.StatusModified
	if zipper, err := diff.NewZipper(oldFn, newFn, ir.KeepAllLiteralsPolicy); err == nil {
		if artifacts, err := zipper.ComputeDiff(); err == nil {
			d.MatchedNodes, d.AddedOps, d.RemovedOps = artifacts.MatchedNodes, artifacts.Added, artifacts.Removed
		}
	}
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

// withoutPackageInit drops the functions with no source file: the
// synthesized package initializer.
func withoutPackageInit(results []diff.FingerprintResult) []diff.FingerprintResult {
	kept := results[:0:0]
	for _, r := range results {
		if r.Filename != "" {
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
