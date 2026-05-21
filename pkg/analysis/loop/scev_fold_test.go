package loop

import (
	"go/token"
	"math/big"
	"testing"
)

// scevConst is a small constructor helper for readable test expressions.
func scevConst(n int64) *SCEVConstant { return &SCEVConstant{Value: big.NewInt(n)} }

// evalAt evaluates a SCEV at iteration k, failing the test if it is unknown.
func evalAt(t *testing.T, s SCEV, k int64) *big.Int {
	t.Helper()
	v := s.EvaluateAt(big.NewInt(k), nil)
	if v == nil {
		t.Fatalf("SCEV %s did not evaluate at k=%d", s.String(), k)
	}
	return v
}

// applyOp mirrors foldSCEV's arithmetic so tests can assert that folding is
// value-preserving rather than just structurally plausible.
func applyOp(op token.Token, x, y *big.Int) *big.Int {
	res := new(big.Int)
	switch op {
	case token.ADD:
		return res.Add(x, y)
	case token.SUB:
		return res.Sub(x, y)
	case token.MUL:
		return res.Mul(x, y)
	}
	panic("unsupported op")
}

// assertValuePreserving checks that folding left op right yields a SCEV whose
// value matches the operator applied pointwise across several iterations.
func assertValuePreserving(t *testing.T, op token.Token, left, right SCEV, l *Loop) SCEV {
	t.Helper()
	folded := foldSCEV(op, left, right, l)
	for k := int64(0); k < 6; k++ {
		got := evalAt(t, folded, k)
		want := applyOp(op, evalAt(t, left, k), evalAt(t, right, k))
		if got.Cmp(want) != 0 {
			t.Fatalf("foldSCEV(%s) at k=%d: got %s, want %s (folded=%s)",
				op, k, got, want, folded.String())
		}
	}
	return folded
}

func TestFoldConstants(t *testing.T) {
	t.Parallel()
	l := &Loop{}
	got := foldSCEV(token.ADD, scevConst(7), scevConst(5), l)
	c, ok := got.(*SCEVConstant)
	if !ok {
		t.Fatalf("constant ADD did not fold to a constant: %T", got)
	}
	if c.Value.Int64() != 12 {
		t.Errorf("7 + 5: got %s, want 12", c.Value)
	}
	// QUO is intentionally not folded so truncation never hides in the IR.
	if _, ok := foldSCEV(token.QUO, scevConst(8), scevConst(2), l).(*SCEVGenericExpr); !ok {
		t.Error("QUO of constants should remain an opaque expression")
	}
}

func TestFoldAddRecWithInvariant(t *testing.T) {
	t.Parallel()
	l := &Loop{}
	rec := &SCEVAddRec{Start: scevConst(1), Step: scevConst(2), Loop: l} // {1,+,2}

	// {1,+,2} + 5  ->  {6,+,2}
	folded := assertValuePreserving(t, token.ADD, rec, scevConst(5), l)
	ar, ok := folded.(*SCEVAddRec)
	if !ok {
		t.Fatalf("AddRec + const did not stay affine: %T", folded)
	}
	if ar.Loop != l {
		t.Error("folded recurrence lost its loop association")
	}

	// 5 + {1,+,2}  ->  {6,+,2}  (commuted)
	if _, ok := assertValuePreserving(t, token.ADD, scevConst(5), rec, l).(*SCEVAddRec); !ok {
		t.Error("const + AddRec did not stay affine")
	}

	// {1,+,2} - 5  ->  {-4,+,2}
	if _, ok := assertValuePreserving(t, token.SUB, rec, scevConst(5), l).(*SCEVAddRec); !ok {
		t.Error("AddRec - const did not stay affine")
	}

	// 10 - {1,+,2}  ->  {9,+,-2}  (step negated)
	folded = assertValuePreserving(t, token.SUB, scevConst(10), rec, l)
	ar, ok = folded.(*SCEVAddRec)
	if !ok {
		t.Fatalf("const - AddRec did not stay affine: %T", folded)
	}
	if evalAt(t, ar.Step, 0).Int64() != -2 {
		t.Errorf("const - AddRec: step should be negated, got %s", ar.Step.String())
	}

	// {1,+,2} * 3  ->  {3,+,6}
	if _, ok := assertValuePreserving(t, token.MUL, rec, scevConst(3), l).(*SCEVAddRec); !ok {
		t.Error("AddRec * const did not stay affine")
	}
}

func TestFoldAddRecWithAddRec(t *testing.T) {
	t.Parallel()
	l := &Loop{}
	a := &SCEVAddRec{Start: scevConst(1), Step: scevConst(2), Loop: l}  // {1,+,2}
	b := &SCEVAddRec{Start: scevConst(3), Step: scevConst(4), Loop: l}  // {3,+,4}

	// {1,+,2} + {3,+,4}  ->  {4,+,6}
	if _, ok := assertValuePreserving(t, token.ADD, a, b, l).(*SCEVAddRec); !ok {
		t.Error("AddRec + AddRec (same loop) did not stay affine")
	}
	// {1,+,2} - {3,+,4}  ->  {-2,+,-2}
	if _, ok := assertValuePreserving(t, token.SUB, a, b, l).(*SCEVAddRec); !ok {
		t.Error("AddRec - AddRec (same loop) did not stay affine")
	}

	// Recurrence * recurrence is quadratic and must stay opaque.
	if _, ok := foldSCEV(token.MUL, a, b, l).(*SCEVGenericExpr); !ok {
		t.Error("AddRec * AddRec should not be folded into an affine recurrence")
	}
}
