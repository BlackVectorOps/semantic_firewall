package diff

import (
	"fmt"
	"go/token"
	"go/types"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/ir"
	"golang.org/x/tools/go/ssa"
)

// ZipperArtifacts contains the results of the semantic delta analysis.
type ZipperArtifacts struct {
	OldFunction  string
	NewFunction  string
	MatchedNodes int
	Added        []string
	Removed      []string
	Preserved    bool
}

// Zipper implements the semantic delta analysis algorithm.
type Zipper struct {
	oldFn *ssa.Function
	newFn *ssa.Function

	policy ir.LiteralPolicy

	oldCanon *ir.Canonicalizer
	newCanon *ir.Canonicalizer

	valMap   map[ssa.Value]ssa.Value
	instrMap map[ssa.Instruction]ssa.Instruction

	revInstrMap map[ssa.Instruction]ssa.Instruction

	queue []valuePair

	fpCache map[ssa.Instruction]string
}

type valuePair struct {
	old ssa.Value
	new ssa.Value
}

func NewZipper(oldFn, newFn *ssa.Function, policy ir.LiteralPolicy) (*Zipper, error) {
	if oldFn == nil || newFn == nil {
		return nil, fmt.Errorf("cannot analyze nil functions")
	}
	return &Zipper{
		oldFn:       oldFn,
		newFn:       newFn,
		policy:      policy,
		valMap:      make(map[ssa.Value]ssa.Value),
		instrMap:    make(map[ssa.Instruction]ssa.Instruction),
		revInstrMap: make(map[ssa.Instruction]ssa.Instruction),
		queue:       make([]valuePair, 0),
		fpCache:     make(map[ssa.Instruction]string),
	}, nil
}

func (z *Zipper) ComputeDiff() (*ZipperArtifacts, error) {
	z.oldCanon = ir.AcquireCanonicalizer(z.policy)
	defer ir.ReleaseCanonicalizer(z.oldCanon)
	z.newCanon = ir.AcquireCanonicalizer(z.policy)
	defer ir.ReleaseCanonicalizer(z.newCanon)

	// Calls exported methods from the ir package
	z.oldCanon.AnalyzeLoops(z.oldFn)
	z.oldCanon.NormalizeInductionVariables()
	z.newCanon.AnalyzeLoops(z.newFn)
	z.newCanon.NormalizeInductionVariables()

	if err := z.alignAnchors(); err != nil {
		return nil, err
	}

	z.propagate()
	z.matchTerminators()

	return z.isolateDivergence(), nil
}

func (z *Zipper) alignAnchors() error {
	if len(z.oldFn.Params) != len(z.newFn.Params) {
		return fmt.Errorf("parameter count mismatch: %d vs %d", len(z.oldFn.Params), len(z.newFn.Params))
	}

	for i, pOld := range z.oldFn.Params {
		pNew := z.newFn.Params[i]
		if !types.Identical(pOld.Type(), pNew.Type()) {
			return fmt.Errorf("parameter %d type mismatch: %s vs %s", i, pOld.Type(), pNew.Type())
		}
		z.mapValue(pOld, pNew)
	}

	if len(z.oldFn.FreeVars) == len(z.newFn.FreeVars) {
		for i, fvOld := range z.oldFn.FreeVars {
			fvNew := z.newFn.FreeVars[i]
			if types.Identical(fvOld.Type(), fvNew.Type()) {
				z.mapValue(fvOld, fvNew)
			}
		}
	}

	z.alignEntryBlock()
	return nil
}

func (z *Zipper) alignEntryBlock() {
	if len(z.oldFn.Blocks) == 0 || len(z.newFn.Blocks) == 0 {
		return
	}

	bOld := z.oldFn.Blocks[0]
	bNew := z.newFn.Blocks[0]

	const MaxLCSWindow = 100
	lenOld := len(bOld.Instrs)
	if lenOld > MaxLCSWindow {
		lenOld = MaxLCSWindow
	}
	lenNew := len(bNew.Instrs)
	if lenNew > MaxLCSWindow {
		lenNew = MaxLCSWindow
	}

	dp := make([][]int, lenOld+1)
	for i := range dp {
		dp[i] = make([]int, lenNew+1)
	}

	for i := 1; i <= lenOld; i++ {
		for j := 1; j <= lenNew; j++ {
			if z.areEquivalent(bOld.Instrs[i-1], bNew.Instrs[j-1]) {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] > dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}

	i, j := lenOld, lenNew
	for i > 0 && j > 0 {
		iOld := bOld.Instrs[i-1]
		iNew := bNew.Instrs[j-1]

		if z.areEquivalent(iOld, iNew) {
			if _, mapped := z.instrMap[iOld]; !mapped {
				z.recordInstrMatch(iOld, iNew)
				if vOld, okOld := iOld.(ssa.Value); okOld {
					if vNew, okNew := iNew.(ssa.Value); okNew {
						z.mapValue(vOld, vNew)
					}
				}
			}
			i--
			j--
		} else {
			if dp[i-1][j] > dp[i][j-1] {
				i--
			} else {
				j--
			}
		}
	}
}

func (z *Zipper) matchTerminators() {
	collect := func(fn *ssa.Function) []ssa.Instruction {
		var terms []ssa.Instruction
		for _, b := range fn.Blocks {
			if len(b.Instrs) > 0 {
				terms = append(terms, b.Instrs[len(b.Instrs)-1])
			}
		}
		return terms
	}

	oldTerms := collect(z.oldFn)
	newTerms := collect(z.newFn)
	z.matchUsers(oldTerms, newTerms)
}

func (z *Zipper) mapValue(old, new ssa.Value) {
	if _, exists := z.valMap[old]; exists {
		return
	}
	z.valMap[old] = new
	z.queue = append(z.queue, valuePair{old, new})

	if iOld, ok := old.(ssa.Instruction); ok {
		if iNew, ok := new.(ssa.Instruction); ok {
			z.recordInstrMatch(iOld, iNew)
		}
	}
}

func (z *Zipper) recordInstrMatch(old, new ssa.Instruction) {
	if _, exists := z.instrMap[old]; exists {
		return
	}
	z.instrMap[old] = new
	z.revInstrMap[new] = old
}

func (z *Zipper) propagate() {
	queueIdx := 0
	for queueIdx < len(z.queue) {
		curr := z.queue[queueIdx]
		queueIdx++

		refsOldPtr := curr.old.Referrers()
		refsNewPtr := curr.new.Referrers()

		if refsOldPtr == nil || refsNewPtr == nil {
			continue
		}

		z.matchUsers(*refsOldPtr, *refsNewPtr)
	}
	z.queue = z.queue[:0]
}

const MaxCandidates = 100

func (z *Zipper) matchUsers(usersOld, usersNew []ssa.Instruction) {
	newByOp := make(map[string][]ssa.Instruction)
	for _, u := range usersNew {
		if _, mapped := z.revInstrMap[u]; mapped {
			continue
		}
		fp := z.getFingerprint(u)
		if len(newByOp[fp]) < MaxCandidates {
			newByOp[fp] = append(newByOp[fp], u)
		}
	}

	z.sortInstrs(usersOld)

	for _, uOld := range usersOld {
		if _, mapped := z.instrMap[uOld]; mapped {
			continue
		}

		fp := z.getFingerprint(uOld)
		candidates := newByOp[fp]

		if len(candidates) > 1 {
			z.sortInstrs(candidates)
		}

		for _, uNew := range candidates {
			if _, mapped := z.revInstrMap[uNew]; mapped {
				continue
			}

			if z.areEquivalent(uOld, uNew) {
				z.recordInstrMatch(uOld, uNew)

				vOld, isValOld := uOld.(ssa.Value)
				vNew, isValNew := uNew.(ssa.Value)
				if isValOld && isValNew {
					z.mapValue(vOld, vNew)
				}
				break
			}
		}
	}
}

func (z *Zipper) areEquivalent(a, b ssa.Instruction) bool {
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}

	if vA, ok := a.(ssa.Value); ok {
		vB := b.(ssa.Value)
		if !types.Identical(vA.Type(), vB.Type()) {
			return false
		}
	}

	if !z.compareOps(a, b) {
		return false
	}

	return z.compareOperands(a, b)
}

func (z *Zipper) compareOps(a, b ssa.Instruction) bool {
	switch iA := a.(type) {
	case *ssa.BinOp:
		iB := b.(*ssa.BinOp)
		return iA.Op == iB.Op
	case *ssa.UnOp:
		iB := b.(*ssa.UnOp)
		return iA.Op == iB.Op && iA.CommaOk == iB.CommaOk
	case *ssa.Call:
		iB := b.(*ssa.Call)
		if iA.Call.IsInvoke() != iB.Call.IsInvoke() {
			return false
		}
		if iA.Call.IsInvoke() {
			return iA.Call.Method.Name() == iB.Call.Method.Name()
		}
		return true
	case *ssa.Field:
		iB := b.(*ssa.Field)
		return iA.Field == iB.Field
	case *ssa.FieldAddr:
		iB := b.(*ssa.FieldAddr)
		return iA.Field == iB.Field
	case *ssa.Alloc:
		iB := b.(*ssa.Alloc)
		return iA.Heap == iB.Heap
	case *ssa.Extract:
		iB := b.(*ssa.Extract)
		return iA.Index == iB.Index
	case *ssa.Select:
		iB := b.(*ssa.Select)
		return iA.Blocking == iB.Blocking
	case *ssa.ChangeType:
		iB := b.(*ssa.ChangeType)
		return types.Identical(iA.Type(), iB.Type())
	case *ssa.Convert:
		iB := b.(*ssa.Convert)
		return types.Identical(iA.Type(), iB.Type())
	case *ssa.MakeInterface:
		iB := b.(*ssa.MakeInterface)
		return types.Identical(iA.Type(), iB.Type())
	case *ssa.TypeAssert:
		iB := b.(*ssa.TypeAssert)
		return types.Identical(iA.AssertedType, iB.AssertedType) && iA.CommaOk == iB.CommaOk
	case *ssa.MakeSlice:
		iB := b.(*ssa.MakeSlice)
		return types.Identical(iA.Type(), iB.Type())
	case *ssa.MakeMap:
		iB := b.(*ssa.MakeMap)
		return types.Identical(iA.Type(), iB.Type())
	case *ssa.MakeChan:
		iB := b.(*ssa.MakeChan)
		return types.Identical(iA.Type(), iB.Type())
	case *ssa.Slice:
		iB := b.(*ssa.Slice)
		return types.Identical(iA.Type(), iB.Type())
	case *ssa.ChangeInterface:
		iB := b.(*ssa.ChangeInterface)
		return types.Identical(iA.Type(), iB.Type())
	case *ssa.SliceToArrayPointer:
		iB := b.(*ssa.SliceToArrayPointer)
		return types.Identical(iA.Type(), iB.Type())
	}
	return true
}

func IsCommutativeOp(op token.Token) bool {
	switch op {
	case token.ADD, token.MUL, token.AND, token.OR, token.XOR, token.EQL, token.NEQ:
		return true
	}
	return false
}

func (z *Zipper) compareOperands(a, b ssa.Instruction) bool {
	opsA := a.Operands(nil)
	opsB := b.Operands(nil)

	if len(opsA) != len(opsB) {
		return false
	}

	// Logic Refinement: We strictly gate the commutativity check.
	// Previously, we allowed partial fallthroughs which could trigger on strings.
	// Now we define `allowSwap` explicitly based on strict Op and Type rules.
	if binOp, ok := a.(*ssa.BinOp); ok && len(opsA) == 2 {
		allowSwap := false

		// Identify the underlying basic type info (e.g. IsInteger, IsString)
		var basicInfo types.BasicInfo
		isBasic := false
		if basic, ok := binOp.Type().Underlying().(*types.Basic); ok {
			isBasic = true
			basicInfo = basic.Info()
		}

		switch binOp.Op {
		case token.ADD, token.MUL, token.AND, token.OR, token.XOR:
			// For arithmetic/logical ops, commutativity is strictly for numeric types.
			// Specifically exclude String (ADD) here by explicitly checking that IsString is NOT set.
			// This prevents false positives if there's any unexpected overlap in type bits or untyped constants.
			if isBasic && (basicInfo&types.IsString) == 0 && (basicInfo&(types.IsInteger|types.IsFloat|types.IsComplex)) != 0 {
				allowSwap = true
			}
		case token.EQL, token.NEQ:
			// Equality is commutative for ANY comparable type (Integers, Strings, Pointers, Interfaces).
			// Logic: (a == b) is always equivalent to (b == a).
			allowSwap = true
		}

		if allowSwap {
			// Optimization: Try the direct match first as it is cheaper (cache hits).
			if z.compareOperandPair(opsA[0], opsA[1], opsB[0], opsB[1]) {
				return true
			}
			// If direct match fails, attempt the commutative swap.
			return z.compareOperandPair(opsA[0], opsA[1], opsB[1], opsB[0])
		}
	}

	for i, ptrA := range opsA {
		if ptrA == nil || opsB[i] == nil {
			return false
		}
		valA := *ptrA
		valB := *opsB[i]

		if valA == nil && valB == nil {
			continue
		}
		if valA == nil || valB == nil {
			return false
		}

		if mappedB, ok := z.valMap[valA]; ok {
			if mappedB != valB {
				return false
			}
			continue
		}

		IsLinkable := z.isLinkable(valA)

		if IsLinkable {
			if _, isPhi := a.(*ssa.Phi); isPhi {
				if !z.isLinkable(valB) {
					return false
				}
				if valA.Type() != nil && valB.Type() != nil {
					if !types.Identical(valA.Type(), valB.Type()) {
						return false
					}
				}
				continue
			}
			return false
		}

		// Calls exported NormalizeOperand method
		canonA := z.oldCanon.NormalizeOperand(valA, a)
		canonB := z.newCanon.NormalizeOperand(valB, b)

		if canonA != canonB {
			return false
		}
	}
	return true
}

func (z *Zipper) isLinkable(v ssa.Value) bool {
	switch v.(type) {
	case ssa.Instruction, *ssa.Parameter, *ssa.FreeVar:
		return true
	}
	return false
}

func (z *Zipper) compareOperandPair(ptrA0, ptrA1, ptrB0, ptrB1 *ssa.Value) bool {
	return z.compareOneOperand(ptrA0, ptrB0) && z.compareOneOperand(ptrA1, ptrB1)
}

func (z *Zipper) compareOneOperand(ptrA, ptrB *ssa.Value) bool {
	if ptrA == nil || ptrB == nil {
		return false
	}
	valA := *ptrA
	valB := *ptrB

	if valA == nil && valB == nil {
		return true
	}
	if valA == nil || valB == nil {
		return false
	}

	if mappedB, ok := z.valMap[valA]; ok {
		return mappedB == valB
	}

	if z.isLinkable(valA) {
		return false
	}

	// Calls exported NormalizeOperand method
	canonA := z.oldCanon.NormalizeOperand(valA, nil)
	canonB := z.newCanon.NormalizeOperand(valB, nil)
	return canonA == canonB
}

func (z *Zipper) isolateDivergence() *ZipperArtifacts {
	r := &ZipperArtifacts{
		OldFunction:  z.oldFn.RelString(nil),
		NewFunction:  z.newFn.RelString(nil),
		MatchedNodes: len(z.instrMap),
	}

	for _, b := range z.oldFn.Blocks {
		for _, instr := range b.Instrs {
			// Accesses exported VirtualizedInstrs field
			if z.oldCanon.VirtualizedInstrs[instr] {
				continue
			}
			if _, ok := z.instrMap[instr]; !ok {
				r.Removed = append(r.Removed, z.formatInstr(instr))
			}
		}
	}

	for _, b := range z.newFn.Blocks {
		for _, instr := range b.Instrs {
			// Accesses exported VirtualizedInstrs field
			if z.newCanon.VirtualizedInstrs[instr] {
				continue
			}
			if _, ok := z.revInstrMap[instr]; !ok {
				r.Added = append(r.Added, z.formatInstr(instr))
			}
		}
	}

	sort.Strings(r.Added)
	sort.Strings(r.Removed)
	r.Preserved = len(r.Added) == 0 && len(r.Removed) == 0
	return r
}

func (z *Zipper) formatInstr(instr ssa.Instruction) string {
	if v, ok := instr.(ssa.Value); ok && v.Name() != "" {
		return fmt.Sprintf("%s = %s", v.Name(), instr.String())
	}
	return instr.String()
}

type instrSorter struct {
	instrs []ssa.Instruction
	z      *Zipper
}

func (s instrSorter) Len() int      { return len(s.instrs) }
func (s instrSorter) Swap(i, j int) { s.instrs[i], s.instrs[j] = s.instrs[j], s.instrs[i] }
func (s instrSorter) Less(i, j int) bool {
	fi := s.z.getFingerprint(s.instrs[i])
	fj := s.z.getFingerprint(s.instrs[j])
	if fi != fj {
		return fi < fj
	}
	return s.instrs[i].String() < s.instrs[j].String()
}

func (z *Zipper) sortInstrs(instrs []ssa.Instruction) {
	sort.Sort(instrSorter{instrs, z})
}

func (z *Zipper) getFingerprint(instr ssa.Instruction) string {
	if cached, ok := z.fpCache[instr]; ok {
		return cached
	}

	var sb strings.Builder
	if instr == nil {
		sb.WriteString("<nil>")
	} else {
		sb.WriteString(reflect.TypeOf(instr).String())
	}

	switch i := instr.(type) {
	case *ssa.BinOp:
		sb.WriteString(":")
		sb.WriteString(i.Op.String())
	case *ssa.UnOp:
		sb.WriteString(":")
		sb.WriteString(i.Op.String())
	case *ssa.Call:
		if i.Call.IsInvoke() {
			sb.WriteString(":invoke:")
			sb.WriteString(i.Call.Method.Name())
		} else {
			switch v := i.Call.Value.(type) {
			case *ssa.Function:
				sb.WriteString(":call:")
				sb.WriteString(v.RelString(nil))
			case *ssa.Builtin:
				sb.WriteString(":builtin:")
				sb.WriteString(v.Name())
			case *ssa.MakeClosure:
				sb.WriteString(":closure")
				if fn, ok := v.Fn.(*ssa.Function); ok {
					sb.WriteString(":")
					sb.WriteString(fn.Signature.String())
				}
			default:
				if i.Call.Value != nil {
					sb.WriteString(":dynamic:")
					sb.WriteString(i.Call.Value.Type().String())
				} else {
					sb.WriteString(":call")
				}
			}
		}
	case *ssa.Alloc:
		sb.WriteString(":")
		sb.WriteString(i.Type().String())
	case *ssa.Field:
		sb.WriteString(":field:")
		sb.WriteString(strconv.Itoa(i.Field))
	case *ssa.FieldAddr:
		sb.WriteString(":fieldaddr:")
		sb.WriteString(strconv.Itoa(i.Field))
	case *ssa.Index:
		sb.WriteString(":index")
	case *ssa.IndexAddr:
		sb.WriteString(":indexaddr")
	case *ssa.Store:
		sb.WriteString(":store")
	}
	res := sb.String()
	z.fpCache[instr] = res
	return res
}
