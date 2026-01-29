package loop

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"

	"golang.org/x/tools/go/ssa"
)

type Renamer func(ssa.Value) string

const MaxSCEVDepth = 100

type SCEV interface {
	ssa.Value
	EvaluateAt(k *big.Int, cache map[SCEV]*big.Int) *big.Int
	IsLoopInvariant(loop *Loop) bool
	String() string
	StringWithRenamer(r Renamer) string
}

type SCEVAddRec struct {
	Start SCEV
	Step  SCEV
	Loop  *Loop
}

func (s *SCEVAddRec) EvaluateAt(k *big.Int, cache map[SCEV]*big.Int) *big.Int {
	if cache != nil {
		if val, ok := cache[s]; ok {
			return val
		}
	}
	startVal := s.Start.EvaluateAt(k, cache)
	stepVal := s.Step.EvaluateAt(k, cache)
	if startVal == nil || stepVal == nil || k == nil {
		return nil
	}
	term := new(big.Int).Mul(stepVal, k)
	res := new(big.Int).Add(startVal, term)
	if cache != nil {
		cache[s] = res
	}
	return res
}
func (s *SCEVAddRec) IsLoopInvariant(loop *Loop) bool {
	if s.Loop == loop {
		return false
	}
	return s.Start.IsLoopInvariant(loop) && s.Step.IsLoopInvariant(loop)
}
func (s *SCEVAddRec) String() string {
	return fmt.Sprintf("{%s, +, %s}", s.Start.String(), s.Step.String())
}
func (s *SCEVAddRec) StringWithRenamer(r Renamer) string {
	return fmt.Sprintf("{%s, +, %s}", s.Start.StringWithRenamer(r), s.Step.StringWithRenamer(r))
}
func (s *SCEVAddRec) Name() string                  { return "scev_addrec" }
func (s *SCEVAddRec) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVAddRec) Parent() *ssa.Function         { return nil }
func (s *SCEVAddRec) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVAddRec) Pos() token.Pos                { return token.NoPos }

type SCEVConstant struct{ Value *big.Int }

func (s *SCEVConstant) EvaluateAt(k *big.Int, cache map[SCEV]*big.Int) *big.Int {
	return new(big.Int).Set(s.Value)
}
func (s *SCEVConstant) IsLoopInvariant(loop *Loop) bool    { return true }
func (s *SCEVConstant) String() string                     { return s.Value.String() }
func (s *SCEVConstant) StringWithRenamer(r Renamer) string { return s.Value.String() }
func (s *SCEVConstant) Name() string                       { return s.Value.String() }
func (s *SCEVConstant) Type() types.Type                   { return types.Typ[types.Int] }
func (s *SCEVConstant) Parent() *ssa.Function              { return nil }
func (s *SCEVConstant) Referrers() *[]ssa.Instruction      { return nil }
func (s *SCEVConstant) Pos() token.Pos                     { return token.NoPos }

type SCEVUnknown struct {
	Value       ssa.Value
	IsInvariant bool
}

func (s *SCEVUnknown) EvaluateAt(k *big.Int, cache map[SCEV]*big.Int) *big.Int { return nil }
func (s *SCEVUnknown) IsLoopInvariant(loop *Loop) bool {
	if s.IsInvariant {
		return true
	}
	if s.Value == nil {
		return false
	}
	if _, ok := s.Value.(*ssa.Const); ok {
		return true
	}
	if instr, ok := s.Value.(ssa.Instruction); ok {
		return !loop.Blocks[instr.Block()]
	}
	return true
}
func (s *SCEVUnknown) String() string {
	name := "?"
	if s.Value != nil {
		name = s.Value.Name()
	}
	if s.IsInvariant {
		return name + "(inv)"
	}
	return name
}
func (s *SCEVUnknown) StringWithRenamer(r Renamer) string {
	name := "?"
	if s.Value != nil && r != nil {
		name = r(s.Value)
	} else if s.Value != nil {
		name = s.Value.Name()
	}
	if s.IsInvariant {
		return name + "(inv)"
	}
	return name
}
func (s *SCEVUnknown) Name() string                  { return s.String() }
func (s *SCEVUnknown) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVUnknown) Parent() *ssa.Function         { return nil }
func (s *SCEVUnknown) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVUnknown) Pos() token.Pos                { return token.NoPos }

type SCEVGenericExpr struct {
	Op token.Token
	X  SCEV
	Y  SCEV
}

func (s *SCEVGenericExpr) EvaluateAt(k *big.Int, cache map[SCEV]*big.Int) *big.Int {
	if cache != nil {
		if val, ok := cache[s]; ok {
			return val
		}
	}
	xVal := s.X.EvaluateAt(k, cache)
	yVal := s.Y.EvaluateAt(k, cache)
	if xVal == nil || yVal == nil {
		return nil
	}
	res := new(big.Int)
	switch s.Op {
	case token.ADD:
		res.Add(xVal, yVal)
	case token.SUB:
		res.Sub(xVal, yVal)
	case token.MUL:
		res.Mul(xVal, yVal)
	case token.QUO:
		if yVal.Sign() == 0 {
			return nil
		}
		res.Quo(xVal, yVal)
	default:
		return nil
	}
	if cache != nil {
		cache[s] = res
	}
	return res
}
func (s *SCEVGenericExpr) IsLoopInvariant(loop *Loop) bool {
	return s.X.IsLoopInvariant(loop) && s.Y.IsLoopInvariant(loop)
}
func (s *SCEVGenericExpr) String() string {
	return fmt.Sprintf("(%s %s %s)", s.X.String(), s.Op.String(), s.Y.String())
}
func (s *SCEVGenericExpr) StringWithRenamer(r Renamer) string {
	return fmt.Sprintf("(%s %s %s)", s.X.StringWithRenamer(r), s.Op.String(), s.Y.StringWithRenamer(r))
}
func (s *SCEVGenericExpr) Name() string                  { return "scev_expr" }
func (s *SCEVGenericExpr) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVGenericExpr) Parent() *ssa.Function         { return nil }
func (s *SCEVGenericExpr) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVGenericExpr) Pos() token.Pos                { return token.NoPos }

type SCEVMax struct {
	X SCEV
	Y SCEV
}

func (s *SCEVMax) EvaluateAt(k *big.Int, cache map[SCEV]*big.Int) *big.Int {
	if cache != nil {
		if val, ok := cache[s]; ok {
			return val
		}
	}
	xVal := s.X.EvaluateAt(k, cache)
	yVal := s.Y.EvaluateAt(k, cache)
	if xVal == nil || yVal == nil {
		return nil
	}
	var res *big.Int
	if xVal.Cmp(yVal) > 0 {
		res = new(big.Int).Set(xVal)
	} else {
		res = new(big.Int).Set(yVal)
	}
	if cache != nil {
		cache[s] = res
	}
	return res
}
func (s *SCEVMax) IsLoopInvariant(loop *Loop) bool {
	return s.X.IsLoopInvariant(loop) && s.Y.IsLoopInvariant(loop)
}
func (s *SCEVMax) String() string { return fmt.Sprintf("max(%s, %s)", s.X.String(), s.Y.String()) }
func (s *SCEVMax) StringWithRenamer(r Renamer) string {
	return fmt.Sprintf("max(%s, %s)", s.X.StringWithRenamer(r), s.Y.StringWithRenamer(r))
}
func (s *SCEVMax) Name() string                  { return "scev_max" }
func (s *SCEVMax) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVMax) Parent() *ssa.Function         { return nil }
func (s *SCEVMax) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVMax) Pos() token.Pos                { return token.NoPos }

func AnalyzeSCEV(info *LoopInfo) {
	if len(info.Loops) == 0 {
		return
	}
	// Iterative Tree Traversal
	stack := make([]*Loop, len(info.Loops))
	copy(stack, info.Loops)
	for len(stack) > 0 {
		l := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		identifyInductionVariables(l)
		deriveTripCount(l)
		if len(l.Children) > 0 {
			stack = append(stack, l.Children...)
		}
	}
}

func identifyInductionVariables(loop *Loop) {
	var loopInstrs []ssa.Instruction
	for _, block := range loop.Header.Parent().Blocks {
		if loop.Blocks[block] {
			loopInstrs = append(loopInstrs, block.Instrs...)
		}
	}
	sccs := findLoopSCCs(loop, loopInstrs)
	for _, scc := range sccs {
		var headerPhi *ssa.Phi
		for _, instr := range scc {
			if phi, ok := instr.(*ssa.Phi); ok && phi.Block() == loop.Header {
				headerPhi = phi
				break
			}
		}
		if headerPhi == nil {
			continue
		}
		classifyIV(loop, headerPhi, scc)
	}
}

// findLoopSCCs implements an iterative Tarjan's algorithm to avoid stack overflow.
func findLoopSCCs(loop *Loop, instrs []ssa.Instruction) [][]ssa.Instruction {
	var sccs [][]ssa.Instruction
	index := 0
	indices := make(map[ssa.Instruction]int)
	lowLink := make(map[ssa.Instruction]int)
	stack := []ssa.Instruction{}
	onStack := make(map[ssa.Instruction]bool)

	type frame struct {
		v         ssa.Instruction
		neighbors []ssa.Instruction
		nextIdx   int
	}

	nodes := make(map[ssa.Instruction]bool)
	for _, instr := range instrs {
		nodes[instr] = true
	}

	for _, root := range instrs {
		if _, visited := indices[root]; visited {
			continue
		}

		workStack := []*frame{{v: root}}

		for len(workStack) > 0 {
			f := workStack[len(workStack)-1]
			v := f.v

			if f.nextIdx == 0 {
				indices[v] = index
				lowLink[v] = index
				index++
				stack = append(stack, v)
				onStack[v] = true

				ops := v.Operands(nil)
				for _, op := range ops {
					if w, ok := (*op).(ssa.Instruction); ok && nodes[w] {
						f.neighbors = append(f.neighbors, w)
					}
				}
			}

			pushedNeighbor := false
			for f.nextIdx < len(f.neighbors) {
				w := f.neighbors[f.nextIdx]
				f.nextIdx++

				if _, visited := indices[w]; !visited {
					workStack = append(workStack, &frame{v: w})
					pushedNeighbor = true
					break
				} else if onStack[w] {
					if indices[w] < lowLink[v] {
						lowLink[v] = indices[w]
					}
				}
			}

			if pushedNeighbor {
				continue
			}

			workStack = workStack[:len(workStack)-1]

			if len(workStack) > 0 {
				parent := workStack[len(workStack)-1].v
				if lowLink[v] < lowLink[parent] {
					lowLink[parent] = lowLink[v]
				}
			}

			if lowLink[v] == indices[v] {
				var component []ssa.Instruction
				for {
					if len(stack) == 0 {
						break
					}
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					component = append(component, w)
					if w == v {
						break
					}
				}
				sccs = append(sccs, component)
			}
		}
	}
	return sccs
}

func classifyIV(loop *Loop, phi *ssa.Phi, scc []ssa.Instruction) {
	var binOp *ssa.BinOp
	for _, instr := range scc {
		if op, ok := instr.(*ssa.BinOp); ok {
			if op.X == phi || op.Y == phi {
				binOp = op
				break
			}
		}
	}
	if binOp == nil {
		return
	}

	// Type Check: Ensure we only process Integers (prevent float loops)
	isInteger := false
	if basic, ok := binOp.Type().Underlying().(*types.Basic); ok {
		if (basic.Info() & types.IsInteger) != 0 {
			isInteger = true
		}
	}
	if !isInteger {
		return
	}

	var stepVal ssa.Value
	if binOp.X == phi {
		stepVal = binOp.Y
	} else if binOp.Y == phi {
		if binOp.Op == token.SUB {
			return
		}
		stepVal = binOp.X
	} else {
		return
	}

	stepSCEV := ToSCEV(stepVal, loop)
	if !stepSCEV.IsLoopInvariant(loop) {
		return
	}

	var startVal ssa.Value
	for i, pred := range phi.Block().Preds {
		if !loop.Blocks[pred] {
			if startVal == nil {
				startVal = phi.Edges[i]
			} else if startVal != phi.Edges[i] {
				return
			}
		} else {
			// Security/Correctness Fix: Back-edge verification
			if phi.Edges[i] != binOp {
				return
			}
		}
	}
	if startVal == nil {
		return
	}
	startSCEV := ToSCEV(startVal, loop)

	iv := &InductionVariable{Phi: phi, Start: startSCEV, Step: stepSCEV}
	switch binOp.Op {
	case token.ADD:
		iv.Type = IVTypeBasic
	case token.SUB:
		iv.Type = IVTypeBasic
		if c, ok := stepSCEV.(*SCEVConstant); ok {
			neg := new(big.Int).Neg(c.Value)
			iv.Step = &SCEVConstant{Value: neg}
		} else {
			iv.Step = &SCEVGenericExpr{Op: token.MUL, X: stepSCEV, Y: &SCEVConstant{Value: big.NewInt(-1)}}
		}
	case token.MUL:
		iv.Type = IVTypeGeometric
	default:
		return
	}
	loop.Inductions[phi] = iv
}

func deriveTripCount(loop *Loop) {
	if len(loop.Exits) != 1 {
		loop.TripCount = &SCEVUnknown{Value: nil}
		return
	}
	exitBlock := loop.Exits[0]
	if len(exitBlock.Instrs) == 0 {
		return
	}
	ifInstr, ok := exitBlock.Instrs[len(exitBlock.Instrs)-1].(*ssa.If)
	if !ok {
		return
	}
	binOp, ok := ifInstr.Cond.(*ssa.BinOp)
	if !ok {
		return
	}

	var isUpCounting, ivOnLeft bool
	var isInclusive, isNEQ bool

	switch binOp.Op {
	case token.LSS:
		isUpCounting = true
		ivOnLeft = true
	case token.LEQ:
		isUpCounting = true
		ivOnLeft = true
		isInclusive = true
	case token.GTR:
		isUpCounting = false
		ivOnLeft = true
	case token.GEQ:
		isUpCounting = false
		ivOnLeft = true
		isInclusive = true
	case token.NEQ:
		isNEQ = true
		ivOnLeft = true
	default:
		loop.TripCount = &SCEVUnknown{Value: nil}
		return
	}

	var iv *InductionVariable
	var limit ssa.Value
	findIV := func(v ssa.Value) *InductionVariable {
		if phi, ok := v.(*ssa.Phi); ok {
			return loop.Inductions[phi]
		}
		return nil
	}
	if found := findIV(binOp.X); found != nil {
		iv = found
		limit = binOp.Y
	} else if found := findIV(binOp.Y); found != nil {
		iv = found
		limit = binOp.X
		ivOnLeft = !ivOnLeft
		if !isNEQ {
			isUpCounting = !isUpCounting
		}
	}
	if iv == nil || iv.Type != IVTypeBasic {
		return
	}

	limitSCEV := ToSCEV(limit, loop)
	if !limitSCEV.IsLoopInvariant(loop) {
		return
	}

	zero := &SCEVConstant{Value: big.NewInt(0)}

	// Verify Direction for Safety
	startC := iv.Start.EvaluateAt(nil, nil)
	limitC := limitSCEV.EvaluateAt(nil, nil)
	stepC := iv.Step.EvaluateAt(nil, nil)

	if startC != nil && limitC != nil && stepC != nil {
		if !isNEQ {
			// Determine if Dead (TripCount 0) or Divergent (Unknown)
			isDead := false
			if isUpCounting {
				// Condition: i < limit. Loop runs if Start < Limit.
				if startC.Cmp(limitC) >= 0 {
					// Condition is false immediately.
					isDead = true
				} else if stepC.Sign() <= 0 {
					// Start < Limit, but step is negative (or zero). Diverges.
					loop.TripCount = &SCEVUnknown{Value: nil}
					return
				}
			} else {
				// Condition: i > limit. Loop runs if Start > Limit.
				if startC.Cmp(limitC) <= 0 {
					isDead = true
				} else if stepC.Sign() >= 0 {
					// Start > Limit, but step is positive. Diverges.
					loop.TripCount = &SCEVUnknown{Value: nil}
					return
				}
			}

			if isDead {
				loop.TripCount = zero
				return
			}
		} else {
			// NEQ case: i != limit.
			// Runs if Start != Limit.
			if startC.Cmp(limitC) == 0 {
				loop.TripCount = zero
				return
			}
			// If step goes away from limit, it's divergent, but NEQ logic handles
			// exact counts below. If it never hits, it's infinite.
		}
	}

	if isNEQ {
		// NEQ only valid for step 1 or -1
		stepVal := iv.Step.EvaluateAt(nil, nil)
		if stepVal == nil {
			return
		}
		var rawCount SCEV
		if stepVal.Cmp(big.NewInt(1)) == 0 {
			rawCount = &SCEVGenericExpr{Op: token.SUB, X: limitSCEV, Y: iv.Start}
		} else if stepVal.Cmp(big.NewInt(-1)) == 0 {
			rawCount = &SCEVGenericExpr{Op: token.SUB, X: iv.Start, Y: limitSCEV}
		} else {
			return
		}
		// Clamp: max(0, count)
		loop.TripCount = &SCEVMax{X: zero, Y: rawCount}
		return
	}

	if isUpCounting {
		diff := &SCEVGenericExpr{Op: token.SUB, X: limitSCEV, Y: iv.Start}
		var numer SCEV
		if isInclusive {
			numer = &SCEVGenericExpr{Op: token.ADD, X: diff, Y: iv.Step}
		} else {
			one := &SCEVConstant{Value: big.NewInt(1)}
			term1 := &SCEVGenericExpr{Op: token.ADD, X: diff, Y: iv.Step}
			numer = &SCEVGenericExpr{Op: token.SUB, X: term1, Y: one}
		}
		quotient := &SCEVGenericExpr{Op: token.QUO, X: numer, Y: iv.Step}
		loop.TripCount = &SCEVMax{X: zero, Y: quotient}
		return
	}

	if !isUpCounting {
		diff := &SCEVGenericExpr{Op: token.SUB, X: iv.Start, Y: limitSCEV}
		negOne := &SCEVConstant{Value: big.NewInt(-1)}
		absStep := &SCEVGenericExpr{Op: token.MUL, X: iv.Step, Y: negOne}
		var numer SCEV
		if isInclusive {
			numer = &SCEVGenericExpr{Op: token.ADD, X: diff, Y: absStep}
		} else {
			one := &SCEVConstant{Value: big.NewInt(1)}
			term1 := &SCEVGenericExpr{Op: token.ADD, X: diff, Y: absStep}
			numer = &SCEVGenericExpr{Op: token.SUB, X: term1, Y: one}
		}
		quotient := &SCEVGenericExpr{Op: token.QUO, X: numer, Y: absStep}
		loop.TripCount = &SCEVMax{X: zero, Y: quotient}
	}
}

func ToSCEV(v ssa.Value, loop *Loop) SCEV {
	if loop.SCEVCache == nil {
		loop.SCEVCache = make(map[ssa.Value]SCEV)
	}
	if cached, ok := loop.SCEVCache[v]; ok {
		return cached
	}
	res := computeSCEV(v, loop, 0)
	loop.SCEVCache[v] = res
	return res
}

func computeSCEV(v ssa.Value, loop *Loop, depth int) SCEV {
	if loop.SCEVCache != nil {
		if cached, ok := loop.SCEVCache[v]; ok {
			return cached
		}
	}
	if depth > MaxSCEVDepth {
		return &SCEVUnknown{Value: v, IsInvariant: false}
	}
	res := computeSCEVBody(v, loop, depth)
	if loop.SCEVCache != nil {
		loop.SCEVCache[v] = res
	}
	return res
}

func computeSCEVBody(v ssa.Value, loop *Loop, depth int) SCEV {
	if c, ok := v.(*ssa.Const); ok {
		return SCEVFromConst(c)
	}
	if phi, ok := v.(*ssa.Phi); ok {
		if phi.Block() == loop.Header {
			if iv, exists := loop.Inductions[phi]; exists {
				return &SCEVAddRec{Start: iv.Start, Step: iv.Step, Loop: loop}
			}
		}
		return &SCEVUnknown{Value: v, IsInvariant: false}
	}
	if binOp, ok := v.(*ssa.BinOp); ok {
		left := computeSCEV(binOp.X, loop, depth+1)
		right := computeSCEV(binOp.Y, loop, depth+1)
		return foldSCEV(binOp.Op, left, right, loop)
	}
	if instr, ok := v.(ssa.Instruction); ok {
		block := instr.Block()
		return &SCEVUnknown{Value: v, IsInvariant: block != nil && !loop.Blocks[block]}
	}
	return &SCEVUnknown{Value: v, IsInvariant: true}
}

func SCEVFromConst(c *ssa.Const) SCEV {
	if c.Value == nil {
		return &SCEVConstant{Value: big.NewInt(0)}
	}
	if c.Value.Kind() == constant.Int {
		if i, ok := new(big.Int).SetString(c.Value.ExactString(), 0); ok {
			return &SCEVConstant{Value: i}
		}
	}
	// Security: Return Unknown for non-integer constants (floats, complex)
	// to prevent logic errors where step 1.5 is treated as step 0.
	return &SCEVUnknown{Value: c, IsInvariant: true}
}

func foldSCEV(op token.Token, left, right SCEV, loop *Loop) SCEV {
	return &SCEVGenericExpr{Op: op, X: left, Y: right}
}
