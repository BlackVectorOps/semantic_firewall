package diff

import (
	"go/types"
	"sort"
	"strconv"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/topology"
	"golang.org/x/tools/go/ssa"
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
		oldByName[pairingName(r)] = r
	}
	for _, r := range newResults {
		newByName[pairingName(r)] = r
	}

	matchedOld := make(map[string]bool)
	matchedNew := make(map[string]bool)

	// Iterate in name order: map order would make the output order, and how
	// equal-similarity rename candidates are paired, vary from run to run.
	oldNames := sortedKeys(oldByName)
	newNames := sortedKeys(newByName)

	// Phase 1: Direct matches by Name. Closure names ("F$1", "F$2") only
	// record creation order, which shifts when a closure is inserted, so
	// closures are paired by content within their enclosing function
	// instead; so are a package's declared initializers ("init#1"), which
	// go/ssa numbers across its files, so another file's init renumbers them.
	for _, name := range oldNames {
		if _, byContent := contentGroup(name); byContent {
			continue
		}
		if newR, ok := newByName[name]; ok {
			matched = append(matched, sameFunctionMatch(oldByName[name], newR))
			matchedOld[name] = true
			matchedNew[name] = true
		}
	}
	matched = append(matched, matchClosures(oldByName, newByName, oldNames, newNames, matchedOld, matchedNew, threshold)...)

	var unmatchedOld []FingerprintResult
	var unmatchedNew []FingerprintResult

	for _, name := range oldNames {
		if !matchedOld[name] {
			unmatchedOld = append(unmatchedOld, oldByName[name])
		}
	}
	for _, name := range newNames {
		if !matchedNew[name] {
			unmatchedNew = append(unmatchedNew, newByName[name])
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

// sameFunctionMatch pairs two versions of what is known to be the same
// function.
func sameFunctionMatch(oldR, newR FingerprintResult) TopologyMatch {
	var oldTopo, newTopo *topology.FunctionTopology
	if fn := oldR.GetSSAFunction(); fn != nil {
		oldTopo = topology.ExtractTopology(fn)
	}
	if fn := newR.GetSSAFunction(); fn != nil {
		newTopo = topology.ExtractTopology(fn)
	}
	sim := 1.0
	if oldTopo != nil && newTopo != nil {
		sim = topology.TopologySimilarity(oldTopo, newTopo)
	}
	return TopologyMatch{
		OldResult:   oldR,
		NewResult:   newR,
		OldTopology: oldTopo,
		NewTopology: newTopo,
		Similarity:  sim,
		ByName:      true,
	}
}

// contentGroup returns the group within which a function is paired by
// content, and whether it is: the enclosing named function of a closure,
// and "init#" for the declared initializers and their closures.
func contentGroup(name string) (string, bool) {
	parent, closure := closureParent(name)
	if !closure {
		parent = name
	}
	if n, ok := strings.CutPrefix(parent, "init#"); ok && isNumber(n) {
		return "init#", true
	}
	return parent, closure
}

func isNumber(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// closureParent returns the enclosing named function of a closure name
// ("F" for "F$2" and "F$1$3").
func closureParent(name string) (string, bool) {
	i := strings.IndexByte(name, '$')
	if i <= 0 {
		return "", false
	}
	for _, part := range strings.Split(name[i+1:], "$") {
		if !isNumber(part) {
			return "", false
		}
	}
	return name[:i], true
}

// matchClosures pairs the closures of each enclosing function, and the
// declared initializers with their closures (see contentGroup), in four
// passes: identical fingerprints with every literal kept (unchanged
// closures, however their numbers shifted), identical default fingerprints
// (closures that changed only a literal), topology similarity of at least
// threshold, best first, and finally identical names for what remains.
// Paired names are marked in matchedOld and matchedNew; unpaired closures
// fall through to the global topology phase.
func matchClosures(oldByName, newByName map[string]FingerprintResult, oldNames, newNames []string,
	matchedOld, matchedNew map[string]bool, threshold float64) []TopologyMatch {

	group := func(names []string) map[string][]string {
		g := make(map[string][]string)
		for _, n := range names {
			if parent, ok := contentGroup(n); ok {
				g[parent] = append(g[parent], n)
			}
		}
		return g
	}
	oldGroups, newGroups := group(oldNames), group(newNames)
	parents := make([]string, 0, len(oldGroups))
	for p := range oldGroups {
		if _, ok := newGroups[p]; ok {
			parents = append(parents, p)
		}
	}
	sort.Strings(parents)

	var out []TopologyMatch
	pair := func(o, n string) {
		out = append(out, sameFunctionMatch(oldByName[o], newByName[n]))
		matchedOld[o] = true
		matchedNew[n] = true
	}

	keepAll := make(map[*ssa.Function]string)
	exact := func(r FingerprintResult) string {
		fn := r.GetSSAFunction()
		if fn == nil {
			return ""
		}
		if fp, ok := keepAll[fn]; ok {
			return fp
		}
		fp := GenerateFingerprint(fn, ir.KeepAllLiteralsPolicy, false).Fingerprint
		keepAll[fn] = fp
		return fp
	}

	for _, p := range parents {
		olds, news := oldGroups[p], newGroups[p]

		for _, fp := range []func(FingerprintResult) string{
			exact,
			func(r FingerprintResult) string { return r.Fingerprint },
		} {
			for _, o := range olds {
				if matchedOld[o] {
					continue
				}
				for _, n := range news {
					if !matchedNew[n] && fp(oldByName[o]) != "" && fp(oldByName[o]) == fp(newByName[n]) {
						pair(o, n)
						break
					}
				}
			}
		}

		type candidate struct {
			o, n string
			sim  float64
		}
		newTopos := make(map[string]*topology.FunctionTopology)
		for _, n := range news {
			if fn := newByName[n].GetSSAFunction(); fn != nil && !matchedNew[n] {
				newTopos[n] = topology.ExtractTopology(fn)
			}
		}
		var candidates []candidate
		for _, o := range olds {
			if matchedOld[o] {
				continue
			}
			oldFn := oldByName[o].GetSSAFunction()
			if oldFn == nil {
				continue
			}
			oldTopo := topology.ExtractTopology(oldFn)
			for _, n := range news {
				newTopo := newTopos[n]
				if matchedNew[n] || oldTopo == nil || newTopo == nil {
					continue
				}
				if sim := topology.TopologySimilarity(oldTopo, newTopo); sim >= threshold {
					candidates = append(candidates, candidate{o, n, sim})
				}
			}
		}
		sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].sim > candidates[j].sim })
		for _, c := range candidates {
			if !matchedOld[c.o] && !matchedNew[c.n] {
				pair(c.o, c.n)
			}
		}

		for _, o := range olds {
			if !matchedOld[o] && !matchedNew[o] {
				if _, ok := newByName[o]; ok {
					pair(o, o)
				}
			}
		}
	}
	return out
}

// pairingName is the name two versions of a function are paired by: its
// short name with each type parameter replaced by its position, so renaming
// the type parameter of "(*List[T]).Push" to E does not unpair the method.
func pairingName(r FingerprintResult) string {
	name := ShortFuncName(r.FunctionName)
	fn := r.GetSSAFunction()
	if fn == nil || !strings.Contains(name, "[") {
		return name
	}
	positions := make(map[string]string)
	for f := fn; f != nil; f = f.Parent() {
		for _, tps := range []*types.TypeParamList{f.Signature.RecvTypeParams(), f.Signature.TypeParams()} {
			for i := 0; i < tps.Len(); i++ {
				if n := tps.At(i).Obj().Name(); positions[n] == "" {
					positions[n] = "#" + strconv.Itoa(len(positions))
				}
			}
		}
	}
	if len(positions) == 0 {
		return name
	}
	return replaceTypeParamWords(name, positions)
}

// replaceTypeParamWords replaces each unqualified identifier inside brackets
// that is a key of positions. Type parameters appear only inside the
// brackets of a receiver or function type.
func replaceTypeParamWords(name string, positions map[string]string) string {
	var sb strings.Builder
	depth := 0
	for i := 0; i < len(name); {
		c := name[i]
		switch {
		case c == '[':
			depth++
		case c == ']':
			depth--
		case isIdentByte(c) && depth > 0:
			j := i
			for j < len(name) && isIdentByte(name[j]) {
				j++
			}
			word := name[i:j]
			qualified := (i > 0 && name[i-1] == '.') || (j < len(name) && name[j] == '.')
			if pos, ok := positions[word]; ok && !qualified {
				word = pos
			}
			sb.WriteString(word)
			i = j
			continue
		}
		sb.WriteByte(c)
		i++
	}
	return sb.String()
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= 0x80 || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func sortedKeys(m map[string]FingerprintResult) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func ShortFuncName(fullName string) string {
	var sb strings.Builder
	// We want to process "words".
	// A word is a sequence of non-separator characters.
	// Separators: ( ) [ ] * , <space> { }
	// Note: '.' and '/' are part of the word.

	lastSep := -1
	for i := 0; i < len(fullName); i++ {
		c := fullName[i]
		isSep := false
		switch c {
		case '(', ')', '[', ']', '*', ',', ' ', '{', '}':
			isSep = true
		}

		if isSep {
			// Process the previous word
			if i > lastSep+1 {
				word := fullName[lastSep+1 : i]
				sb.WriteString(shortenWord(word))
			}
			sb.WriteByte(c)
			lastSep = i
		}
	}
	// Process last word
	if len(fullName) > lastSep+1 {
		word := fullName[lastSep+1:]
		sb.WriteString(shortenWord(word))
	}

	return sb.String()
}

func shortenWord(w string) string {
	if strings.HasPrefix(w, "...") {
		return "..." + shortenWord(w[3:])
	}
	if strings.HasPrefix(w, ".") {
		// Preserve leading dot (e.g. .Method)
		return "." + shortenWord(w[1:])
	}

	lastSlash := strings.LastIndexByte(w, '/')

	// Search for last dot after lastSlash
	lastDot := strings.LastIndexByte(w, '.')

	if lastDot > lastSlash {
		// Dot is in the name part
		return w[lastDot+1:]
	}

	// No dot in the name part. Return the name part (after slash).
	if lastSlash != -1 {
		return w[lastSlash+1:]
	}

	// No slash, no dot (or dot was before slash - impossible if lastDot checked properly?
	// Wait, LastIndexByte finds the very last one.
	// If lastDot < lastSlash, it means there are dots in path, but none in name.

	return w
}
