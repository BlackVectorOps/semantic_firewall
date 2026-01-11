package semanticfw

import (
	"go/constant"
	"testing"

	"golang.org/x/tools/go/ssa"
)

// TestBug_BlindReturnMatching reproduces the issue where returns were paired
// by block index without checking operands.
func TestBug_BlindReturnMatching(t *testing.T) {
	oldFn := &ssa.Function{Blocks: []*ssa.BasicBlock{{Index: 0}}}
	newFn := &ssa.Function{Blocks: []*ssa.BasicBlock{{Index: 0}}}

	// Old: return 1
	c1 := &ssa.Const{Value: constant.MakeInt64(1)}
	ret1 := &ssa.Return{Results: []ssa.Value{c1}}
	oldFn.Blocks[0].Instrs = []ssa.Instruction{ret1}

	// New: return 2
	c2 := &ssa.Const{Value: constant.MakeInt64(2)}
	ret2 := &ssa.Return{Results: []ssa.Value{c2}}
	newFn.Blocks[0].Instrs = []ssa.Instruction{ret2}

	z, _ := NewZipper(oldFn, newFn, KeepAllLiteralsPolicy)
	z.oldCanon = AcquireCanonicalizer(KeepAllLiteralsPolicy)
	defer ReleaseCanonicalizer(z.oldCanon)
	z.newCanon = AcquireCanonicalizer(KeepAllLiteralsPolicy)
	defer ReleaseCanonicalizer(z.newCanon)

	// Verify that returns are NOT matched blindly
	z.matchTerminators()

	if _, mapped := z.instrMap[ret1]; mapped {
		t.Errorf("Regression: 'return 1' and 'return 2' were incorrectly matched")
	}
}

// TestDoS_Bucketing verifies that matchUsers uses bucketing logic
func TestDoS_Bucketing(t *testing.T) {
	z, _ := NewZipper(&ssa.Function{}, &ssa.Function{}, LiteralPolicy{})
	uOld := &ssa.BinOp{} // Op +
	uNew := &ssa.Call{}  // Op Call

	usersOld := []ssa.Instruction{uOld}
	usersNew := []ssa.Instruction{uNew}

	z.matchUsers(usersOld, usersNew)
	if _, mapped := z.instrMap[uOld]; mapped {
		t.Errorf("Matched completely different instructions")
	}
}
