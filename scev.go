package semanticfw

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"

	"golang.org/x/tools/go/ssa"
)

// -- Section 4: Scalar Evolution (SCEV) Framework --

type Renamer func(ssa.Value) string

// Limits recursion depth in SCEV analysis to prevent stack overflow.
const MaxSCEVDepth = 100

type SCEV interface {
	ssa.Value
	EvaluateAt(k *big.Int) *big.Int
	IsLoopInvariant(loop *Loop) bool
	String() string
	StringWithRenamer(r Renamer) string
}

type SCEVAddRec struct {
	Start SCEV
	Step  SCEV
	Loop  *Loop
}

func (s *SCEVAddRec) EvaluateAt(k *big.Int) *big.Int {
	startVal := s.Start.EvaluateAt(k)
	stepVal := s.Step.EvaluateAt(k)
	if startVal == nil || stepVal == nil {
		return nil
	}
	term := new(big.Int).Mul(stepVal, k)
	return new(big.Int).Add(startVal, term)
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

type SCEVConstant struct {
	Value *big.Int
}

func (s *SCEVConstant) EvaluateAt(k *big.Int) *big.Int {
	return new(big.Int).Set(s.Value)
}
func (s *SCEVConstant) IsLoopInvariant(loop *Loop) bool { return true }
func (s *SCEVConstant) String() string                  { return s.Value.String() }
func (s *SCEVConstant) StringWithRenamer(r Renamer) string {
	return s.Value.String()
}

func (s *SCEVConstant) Name() string                  { return s.Value.String() }
func (s *SCEVConstant) Type() types.Type              { return types.Typ[types.Int] }
func (s *SCEVConstant) Parent() *ssa.Function         { return nil }
func (s *SCEVConstant) Referrers() *[]ssa.Instruction { return nil }
func (s *SCEVConstant) Pos() token.Pos                { return token.NoPos }

type SCEVUnknown struct {
	Value       ssa.Value
	IsInvariant bool
}

func (s *SCEVUnknown) EvaluateAt(k *big.Int) *big.Int { return nil }
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
	var name string
	if s.Value != nil {
		name = s.Value.Name()
	} else {
		name = "?"
	}
	if s.IsInvariant {
		return name + "(inv)"
	}
	return name
}

func (s *SCEVUnknown) StringWithRenamer(r Renamer) string {
	var name string
	if s.Value != nil && r != nil {
		name = r(s.Value)
	} else if s.Value != nil {
		name = s.Value.Name()
	} else {
		name = "?"
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

func (s *SCEVGenericExpr) EvaluateAt(k *big.Int) *big.Int { return nil }
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

// -- Analysis Algorithms --

func AnalyzeSCEV(info *LoopInfo) {
	for _, loop := range info.Loops {
		analyzeLoopRecursively(loop)
	}
}

func analyzeLoopRecursively(loop *Loop) {
	for _, child := range loop.Children {
		analyzeLoopRecursively(child)
	}

	identifyInductionVariables(loop)
	deriveTripCount(loop)
}

func identifyInductionVariables(loop *Loop) {
	var loopInstrs []ssa.Instruction
	for _, block := range loop.Header.Parent().Blocks {
		if loop.Blocks[block] {
			loopInstrs = append(loopInstrs, block.Instrs...)
		}
	}

	// Handle error from SCC detection to prevent processing invalid state
	sccs, err := findLoopSCCs(loop, loopInstrs)
	if err != nil {
		// Log error in a real system; here we just skip analysis for this loop
		return
	}

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

// Return error instead of silently failing or breaking on logic error.
func findLoopSCCs(loop *Loop, instrs []ssa.Instruction) ([][]ssa.Instruction, error) {
	var sccs [][]ssa.Instruction
	index := 0
	indices := make(map[ssa.Instruction]int)
	lowLink := make(map[ssa.Instruction]int)
	stack := []ssa.Instruction{}
	onStack := make(map[ssa.Instruction]bool)

	var recursionError error
	var strongConnect func(v ssa.Instruction)

	strongConnect = func(v ssa.Instruction) {
		if recursionError != nil {
			return
		}

		indices[v] = index
		lowLink[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		ops := v.Operands(nil)
		for _, op := range ops {
			if w, ok := (*op).(ssa.Instruction); ok && loop.Blocks[w.Block()] {
				if _, visited := indices[w]; !visited {
					strongConnect(w)
					if lowLink[w] < lowLink[v] {
						lowLink[v] = lowLink[w]
					}
				} else if onStack[w] {
					if indices[w] < lowLink[v] {
						lowLink[v] = indices[w]
					}
				}
			}
		}

		if lowLink[v] == indices[v] {
			var component []ssa.Instruction
			for {
				// Handle stack emptiness gracefully by reporting logic error.
				if len(stack) == 0 {
					recursionError = fmt.Errorf("SCC stack corrupted: expected node %v but stack was empty", v)
					return
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

	for _, instr := range instrs {
		if _, visited := indices[instr]; !visited {
			strongConnect(instr)
			if recursionError != nil {
				return nil, recursionError
			}
		}
	}
	return sccs, nil
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

	stepSCEV := toSCEV(stepVal, loop)
	if !stepSCEV.IsLoopInvariant(loop) {
		return
	}

	var startVal ssa.Value
	for i, pred := range phi.Block().Preds {
		if !loop.Blocks[pred] {
			if startVal == nil {
				startVal = phi.Edges[i]
			} else {
				if startVal != phi.Edges[i] {
					c1, ok1 := startVal.(*ssa.Const)
					c2, ok2 := phi.Edges[i].(*ssa.Const)
					if !ok1 || !ok2 {
						return
					}
					// Handle nil pointer check
					if c1.Value == nil || c2.Value == nil {
						return
					}
					if c1.Value.Kind() != c2.Value.Kind() {
						return
					}
					if !constant.Compare(c1.Value, token.EQL, c2.Value) {
						return
					}
				}
			}
		}
	}

	if startVal == nil {
		return
	}
	startSCEV := toSCEV(startVal, loop)

	iv := &InductionVariable{
		Phi:   phi,
		Start: startSCEV,
		Step:  stepSCEV,
	}

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

	var isUpCounting bool
	var ivOnLeft bool
	var isInclusive bool

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
		isUpCounting = !isUpCounting
	}

	if iv == nil || iv.Type != IVTypeBasic {
		return
	}

	limitSCEV := toSCEV(limit, loop)
	if !limitSCEV.IsLoopInvariant(loop) {
		return
	}

	stepConst, stepIsConst := iv.Step.(*SCEVConstant)
	if stepIsConst {
		stepSign := stepConst.Value.Sign()
		if isUpCounting && stepSign <= 0 {
			loop.TripCount = &SCEVUnknown{Value: nil}
			return
		}
		if !isUpCounting && stepSign >= 0 {
			loop.TripCount = &SCEVUnknown{Value: nil}
			return
		}
	}

	var diff SCEV
	if isUpCounting || !ivOnLeft {
		var negStart SCEV
		if sConst, ok := iv.Start.(*SCEVConstant); ok {
			negStart = &SCEVConstant{Value: new(big.Int).Neg(sConst.Value)}
		} else {
			negStart = &SCEVGenericExpr{Op: token.MUL, X: &SCEVConstant{Value: big.NewInt(-1)}, Y: iv.Start}
		}
		diff = foldSCEV(token.ADD, limitSCEV, negStart, loop)
	} else {
		var negLimit SCEV
		if lConst, ok := limitSCEV.(*SCEVConstant); ok {
			negLimit = &SCEVConstant{Value: new(big.Int).Neg(lConst.Value)}
		} else {
			negLimit = &SCEVGenericExpr{Op: token.MUL, X: &SCEVConstant{Value: big.NewInt(-1)}, Y: limitSCEV}
		}
		diff = foldSCEV(token.ADD, iv.Start, negLimit, loop)
	}

	if isInclusive {
		diff = foldSCEV(token.ADD, diff, &SCEVConstant{Value: big.NewInt(1)}, loop)
	}

	if dConst, ok := diff.(*SCEVConstant); ok {
		if dConst.Value.Sign() < 0 {
			loop.TripCount = &SCEVConstant{Value: big.NewInt(0)}
			return
		}
	}

	var effectiveStep SCEV = iv.Step
	if !isUpCounting && stepIsConst && stepConst.Value.Sign() < 0 {
		effectiveStep = &SCEVConstant{Value: new(big.Int).Abs(stepConst.Value)}
	}

	dConst, dOk := diff.(*SCEVConstant)
	sConst, sOk := effectiveStep.(*SCEVConstant)

	if dOk && sOk && sConst.Value.Sign() > 0 {
		if dConst.Value.Sign() <= 0 {
			loop.TripCount = &SCEVConstant{Value: big.NewInt(0)}
			return
		}
		num := new(big.Int).Add(dConst.Value, sConst.Value)
		num.Sub(num, big.NewInt(1))
		res := new(big.Int).Div(num, sConst.Value)
		loop.TripCount = &SCEVConstant{Value: res}
		return
	}

	loop.TripCount = foldSCEV(token.QUO, diff, effectiveStep, loop)
}

// Public wrapper for SCEV analysis that initiates recursion with depth 0.
func toSCEV(v ssa.Value, loop *Loop) SCEV {
	if loop.SCEVCache == nil {
		loop.SCEVCache = make(map[ssa.Value]SCEV)
	}
	if cached, ok := loop.SCEVCache[v]; ok {
		return cached
	}
	// Start recursion with depth 0
	res := computeSCEV(v, loop, 0)
	loop.SCEVCache[v] = res
	return res
}

// Internal worker with recursion depth limiting.
func computeSCEV(v ssa.Value, loop *Loop, depth int) SCEV {
	// Check recursion depth to prevent stack overflow
	if depth > MaxSCEVDepth {
		return &SCEVUnknown{Value: v, IsInvariant: false}
	}

	if c, ok := v.(*ssa.Const); ok {
		return SCEVFromConst(c)
	}

	if instr, ok := v.(ssa.Instruction); ok {
		block := instr.Block()
		if block != nil && !loop.Blocks[block] {
			return &SCEVUnknown{Value: v, IsInvariant: true}
		}
	}

	if phi, ok := v.(*ssa.Phi); ok {
		if phi.Block() == loop.Header {
			if iv, exists := loop.Inductions[phi]; exists {
				return &SCEVAddRec{
					Start: iv.Start,
					Step:  iv.Step,
					Loop:  loop,
				}
			}
		}
		return &SCEVUnknown{Value: v, IsInvariant: false}
	}

	if binOp, ok := v.(*ssa.BinOp); ok {
		// Pass depth+1 to recursive calls
		leftSCEV := computeSCEV(binOp.X, loop, depth+1)
		rightSCEV := computeSCEV(binOp.Y, loop, depth+1)
		return foldSCEV(binOp.Op, leftSCEV, rightSCEV, loop)
	}

	if instr, ok := v.(ssa.Instruction); ok {
		block := instr.Block()
		isInvariant := block != nil && !loop.Blocks[block]
		return &SCEVUnknown{Value: v, IsInvariant: isInvariant}
	}

	return &SCEVUnknown{Value: v, IsInvariant: true}
}

func SCEVFromConst(c *ssa.Const) *SCEVConstant {
	if c.Value == nil {
		return &SCEVConstant{Value: big.NewInt(0)}
	}
	if c.Value.Kind() == constant.Int {
		if val, ok := constant.Int64Val(c.Value); ok {
			return &SCEVConstant{Value: big.NewInt(val)}
		}
	}
	return &SCEVConstant{Value: big.NewInt(0)}
}

func foldSCEV(op token.Token, left, right SCEV, loop *Loop) SCEV {
	lConst, lIsConst := left.(*SCEVConstant)
	rConst, rIsConst := right.(*SCEVConstant)

	if lIsConst && rIsConst {
		result := new(big.Int)
		switch op {
		case token.ADD:
			result.Add(lConst.Value, rConst.Value)
		case token.SUB:
			result.Sub(lConst.Value, rConst.Value)
		case token.MUL:
			result.Mul(lConst.Value, rConst.Value)
		case token.QUO:
			if rConst.Value.Sign() != 0 {
				result.Div(lConst.Value, rConst.Value)
			} else {
				return &SCEVGenericExpr{Op: op, X: left, Y: right}
			}
		default:
			return &SCEVGenericExpr{Op: op, X: left, Y: right}
		}
		return &SCEVConstant{Value: result}
	}

	if op == token.ADD {
		if addRec, ok := left.(*SCEVAddRec); ok && right.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.ADD, addRec.Start, right, loop)
			return &SCEVAddRec{Start: newStart, Step: addRec.Step, Loop: addRec.Loop}
		}
		if addRec, ok := right.(*SCEVAddRec); ok && left.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.ADD, addRec.Start, left, loop)
			return &SCEVAddRec{Start: newStart, Step: addRec.Step, Loop: addRec.Loop}
		}
	}

	if op == token.SUB {
		if addRec, ok := left.(*SCEVAddRec); ok && right.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.SUB, addRec.Start, right, loop)
			return &SCEVAddRec{Start: newStart, Step: addRec.Step, Loop: addRec.Loop}
		}
	}

	if op == token.MUL {
		if addRec, ok := left.(*SCEVAddRec); ok && right.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.MUL, addRec.Start, right, loop)
			newStep := foldSCEV(token.MUL, addRec.Step, right, loop)
			return &SCEVAddRec{Start: newStart, Step: newStep, Loop: addRec.Loop}
		}
		if addRec, ok := right.(*SCEVAddRec); ok && left.IsLoopInvariant(loop) {
			newStart := foldSCEV(token.MUL, addRec.Start, left, loop)
			newStep := foldSCEV(token.MUL, addRec.Step, left, loop)
			return &SCEVAddRec{Start: newStart, Step: newStep, Loop: addRec.Loop}
		}
	}

	return &SCEVGenericExpr{Op: op, X: left, Y: right}
}
