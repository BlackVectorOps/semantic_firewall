package diff

import (
	"sort"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
)

type TopologyMatch struct {
	OldResult   FingerprintResult
	NewResult   FingerprintResult
	OldTopology *topology.FunctionTopology
	NewTopology *topology.FunctionTopology
	Similarity  float64
	ByName      bool
}

func MatchFunctionsByTopology(oldResults, newResults []FingerprintResult, threshold float64) (
	matched []TopologyMatch,
	addedFuncs []FingerprintResult,
	removedFuncs []FingerprintResult,
) {
	oldByName := make(map[string]FingerprintResult)
	newByName := make(map[string]FingerprintResult)

	for _, r := range oldResults {
		shortName := ShortFuncName(r.FunctionName)
		oldByName[shortName] = r
	}
	for _, r := range newResults {
		shortName := ShortFuncName(r.FunctionName)
		newByName[shortName] = r
	}

	matchedOld := make(map[string]bool)
	matchedNew := make(map[string]bool)

	// Phase 1: Direct matches by Name
	for name, oldR := range oldByName {
		if newR, ok := newByName[name]; ok {
			oldFn := oldR.GetSSAFunction()
			newFn := newR.GetSSAFunction()

			var oldTopo, newTopo *topology.FunctionTopology
			if oldFn != nil {
				oldTopo = topology.ExtractTopology(oldFn)
			}
			if newFn != nil {
				newTopo = topology.ExtractTopology(newFn)
			}

			sim := 1.0
			if oldTopo != nil && newTopo != nil {
				sim = topology.TopologySimilarity(oldTopo, newTopo)
			}

			matched = append(matched, TopologyMatch{
				OldResult:   oldR,
				NewResult:   newR,
				OldTopology: oldTopo,
				NewTopology: newTopo,
				Similarity:  sim,
				ByName:      true,
			})
			matchedOld[name] = true
			matchedNew[name] = true
		}
	}

	var unmatchedOld []FingerprintResult
	var unmatchedNew []FingerprintResult

	for name, r := range oldByName {
		if !matchedOld[name] {
			unmatchedOld = append(unmatchedOld, r)
		}
	}
	for name, r := range newByName {
		if !matchedNew[name] {
			unmatchedNew = append(unmatchedNew, r)
		}
	}

	// Phase 2: Fuzzy matches by Topology
	if len(unmatchedOld) > 0 && len(unmatchedNew) > 0 {
		oldTopos := make([]*topology.FunctionTopology, len(unmatchedOld))
		newTopos := make([]*topology.FunctionTopology, len(unmatchedNew))

		for i, r := range unmatchedOld {
			if fn := r.GetSSAFunction(); fn != nil {
				oldTopos[i] = topology.ExtractTopology(fn)
			}
		}
		for i, r := range unmatchedNew {
			if fn := r.GetSSAFunction(); fn != nil {
				newTopos[i] = topology.ExtractTopology(fn)
			}
		}

		type candidate struct {
			oldIdx int
			newIdx int
			sim    float64
		}

		// Optimization: Group new functions by FuzzyHash.
		newBuckets := make(map[string][]int)
		for j, newTopo := range newTopos {
			if newTopo == nil {
				continue
			}
			newBuckets[newTopo.FuzzyHash] = append(newBuckets[newTopo.FuzzyHash], j)
		}

		// Pre-allocate to avoid frequent resizing
		candidates := make([]candidate, 0, len(oldTopos)*2)

		for i, oldTopo := range oldTopos {
			if oldTopo == nil {
				continue
			}

			// Only compare against candidates in the same structural bucket
			if indices, ok := newBuckets[oldTopo.FuzzyHash]; ok {
				for _, j := range indices {
					newTopo := newTopos[j]

					if newTopo == nil {
						continue
					}

					sim := topology.TopologySimilarity(oldTopo, newTopo)
					if sim >= threshold {
						candidates = append(candidates, candidate{i, j, sim})
					}
				}
			}
		}

		// Use sort.SliceStable for deterministic ordering.
		sort.SliceStable(candidates, func(i, j int) bool {
			return candidates[i].sim > candidates[j].sim
		})

		usedOld := make(map[int]bool)
		usedNew := make(map[int]bool)

		for _, c := range candidates {
			if usedOld[c.oldIdx] || usedNew[c.newIdx] {
				continue
			}

			matched = append(matched, TopologyMatch{
				OldResult:   unmatchedOld[c.oldIdx],
				NewResult:   unmatchedNew[c.newIdx],
				OldTopology: oldTopos[c.oldIdx],
				NewTopology: newTopos[c.newIdx],
				Similarity:  c.sim,
				ByName:      false,
			})
			usedOld[c.oldIdx] = true
			usedNew[c.newIdx] = true
		}

		for i, r := range unmatchedOld {
			if !usedOld[i] {
				removedFuncs = append(removedFuncs, r)
			}
		}
		for i, r := range unmatchedNew {
			if !usedNew[i] {
				addedFuncs = append(addedFuncs, r)
			}
		}
	} else {
		removedFuncs = unmatchedOld
		addedFuncs = unmatchedNew
	}

	return matched, addedFuncs, removedFuncs
}

func ShortFuncName(fullName string) string {
	// FIX: Handle nested parenthesis and brackets (generics)
	// Scan backwards to find the package separator '/' at depth 0.
	depth := 0
	start := 0
	for i := len(fullName) - 1; i >= 0; i-- {
		ch := fullName[i]
		if ch == ')' || ch == ']' {
			depth++
		} else if ch == '(' || ch == '[' {
			depth--
		} else if ch == '/' && depth == 0 {
			start = i + 1
			break
		}
	}

	name := fullName[start:]

	// Scan forward to find the first dot at depth 0.
	depth = 0
	for i, ch := range name {
		switch ch {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case '.':
			if depth == 0 {
				return name[i+1:]
			}
		}
	}
	return name
}
