package detection_test

import (
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/testutil"
)

// SSA shares one instance between call sites whose type arguments are
// identical, spelled as the call site built first. A signature indexed from
// a function must match the same function in a program where another
// caller, with the other spelling, was built first; a required call spelled
// differently would clear the match.
func TestMatch_InstanceSpellingStability(t *testing.T) {
	t.Parallel()

	const decls = `package main
		type Alias = []byte
		type Box[T any] struct{ v T }
		func (b *Box[T]) Get() T { return b.v }
		func has[S ~[]E, E comparable](s S, v E) bool {
			for _, x := range s { if x == v { return true } }
			return false
		}
		func first[T any](xs []T) T { return xs[0] }
		func id[T any](v T) T { return v }
	`
	const target = `
		func target(b []byte, r []rune, a Alias, x any, bx *Box[byte]) bool {
			_ = first(r)
			_ = first(a)
			_ = id(x)
			_ = bx.Get()
			return has(b, 'x')
		}
	`
	const other = `
		func other(b []uint8, r []int32, a []uint8, x interface{}, bx *Box[uint8]) bool {
			_ = first(r)
			_ = first(a)
			_ = id(x)
			_ = bx.Get()
			return has(b, 'x')
		}
	`

	indexed := topology.ExtractTopology(testutil.CompileAndGetFunction(t, decls+target+other, "target"))
	scanned := topology.ExtractTopology(testutil.CompileAndGetFunction(t, decls+other+target, "target"))
	sig := detection.IndexFunction(indexed, "target", "", "HIGH", "test")

	res := detection.NewMatcher(scanned, "target").Match(sig, 0.5)
	if res.MatchDetails.TopologySimilarity != 1.0 || len(res.MatchDetails.CallsMissing) > 0 || res.Confidence == 0 {
		t.Errorf("same function, other caller built first: topology similarity %.2f, missing calls %q, confidence %.2f; want 1.00, none, > 0\nindexed calls: %v\nscanned calls: %v",
			res.MatchDetails.TopologySimilarity, res.MatchDetails.CallsMissing, res.Confidence, indexed.CallSignatures, scanned.CallSignatures)
	}
}
