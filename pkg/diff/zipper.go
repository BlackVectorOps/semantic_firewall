package diff

import (
	"fmt"
	"go/token"
	"go/types"
	"reflect"
	"sort"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/ir"
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

	// oldTP and newTP render each side's type parameters by position, so a
	// type-parameter rename does not unmatch the instructions that use it.
	oldTP, newTP *ir.TypeParamRenamer
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
		oldTP:       ir.NewTypeParamRenamer(oldFn),
		newTP:       ir.NewTypeParamRenamer(newFn),
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

	z.alignAnchors()
	z.propagate()
	z.matchTerminators()

	return z.isolateDivergence(), nil
}

// alignAnchors maps the parameters and free variables the two versions
// share. A signature change does not stop the diff: the uses of a parameter
// without a partner stay unmatched and are reported as added or removed.
func (z *Zipper) alignAnchors() {
	z.alignByName(paramValues(z.oldFn.Params), paramValues(z.newFn.Params))
	z.alignByName(freeVarValues(z.oldFn.FreeVars), freeVarValues(z.newFn.FreeVars))
	z.alignEntryBlock()
}

// alignByName pairs values of the same name and type, then pairs the
// remaining values in order where their types agree, so a renamed parameter
// still aligns while an inserted one does not shift the others.
func (z *Zipper) alignByName(olds, news []ssa.Value) {
	used := make([]bool, len(news))
	var restOld []ssa.Value
	for _, o := range olds {
		paired := false
		for j, n := range news {
			if !used[j] && o.Name() == n.Name() && z.sameType(o.Type(), n.Type()) {
				z.mapValue(o, n)
				used[j], paired = true, true
				break
			}
		}
		if !paired {
			restOld = append(restOld, o)
		}
	}
	var restNew []ssa.Value
	for j, n := range news {
		if !used[j] {
			restNew = append(restNew, n)
		}
	}
	for i := 0; i < len(restOld) && i < len(restNew); i++ {
		if z.sameType(restOld[i].Type(), restNew[i].Type()) {
			z.mapValue(restOld[i], restNew[i])
		}
	}
}

func paramValues(ps []*ssa.Parameter) []ssa.Value {
	vs := make([]ssa.Value, len(ps))
	for i, p := range ps {
		vs[i] = p
	}
	return vs
}

func freeVarValues(fvs []*ssa.FreeVar) []ssa.Value {
	vs := make([]ssa.Value, len(fvs))
	for i, fv := range fvs {
		vs[i] = fv
	}
	return vs
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
		if !z.sameType(vA.Type(), vB.Type()) {
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
		return ir.FieldName(iA.X, iA.Field) == ir.FieldName(iB.X, iB.Field)
	case *ssa.FieldAddr:
		iB := b.(*ssa.FieldAddr)
		return ir.FieldName(iA.X, iA.Field) == ir.FieldName(iB.X, iB.Field)
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
		return z.sameType(iA.Type(), iB.Type())
	case *ssa.Convert:
		iB := b.(*ssa.Convert)
		return z.sameType(iA.Type(), iB.Type())
	case *ssa.MakeInterface:
		iB := b.(*ssa.MakeInterface)
		return z.sameType(iA.Type(), iB.Type())
	case *ssa.TypeAssert:
		iB := b.(*ssa.TypeAssert)
		return z.sameType(iA.AssertedType, iB.AssertedType) && iA.CommaOk == iB.CommaOk
	case *ssa.MakeSlice:
		iB := b.(*ssa.MakeSlice)
		return z.sameType(iA.Type(), iB.Type())
	case *ssa.MakeMap:
		iB := b.(*ssa.MakeMap)
		return z.sameType(iA.Type(), iB.Type())
	case *ssa.MakeChan:
		iB := b.(*ssa.MakeChan)
		return z.sameType(iA.Type(), iB.Type())
	case *ssa.Slice:
		iB := b.(*ssa.Slice)
		return z.sameType(iA.Type(), iB.Type())
	case *ssa.ChangeInterface:
		iB := b.(*ssa.ChangeInterface)
		return z.sameType(iA.Type(), iB.Type())
	case *ssa.SliceToArrayPointer:
		iB := b.(*ssa.SliceToArrayPointer)
		return z.sameType(iA.Type(), iB.Type())
	}
	return true
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
					if !z.sameType(valA.Type(), valB.Type()) {
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
	// Matching follows data flow only, so an instruction moved into or out of
	// a branch, or an If whose targets were swapped, still finds a partner.
	// Such pairs are control-flow changes and are reported as divergent.
	misplaced := z.misplacedPairs()

	r := &ZipperArtifacts{
		OldFunction:  z.oldFn.RelString(nil),
		NewFunction:  z.newFn.RelString(nil),
		MatchedNodes: len(z.instrMap) - len(misplaced),
	}

	for _, b := range z.oldFn.Blocks {
		for _, instr := range b.Instrs {
			// Accesses exported VirtualizedInstrs field
			if z.oldCanon.VirtualizedInstrs[instr] {
				continue
			}
			if _, ok := z.instrMap[instr]; !ok || misplaced[instr] {
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
			if old, ok := z.revInstrMap[instr]; !ok || misplaced[old] {
				r.Added = append(r.Added, z.formatInstr(instr))
			}
		}
	}

	sort.Strings(r.Added)
	sort.Strings(r.Removed)
	r.Preserved = len(r.Added) == 0 && len(r.Removed) == 0 && z.sameParams()
	return r
}

// sameParams reports whether every parameter kept its position and type, so
// an added, removed or retyped parameter is a change even when it is unused.
func (z *Zipper) sameParams() bool {
	if len(z.oldFn.Params) != len(z.newFn.Params) {
		return false
	}
	for i, p := range z.oldFn.Params {
		if z.valMap[p] != ssa.Value(z.newFn.Params[i]) {
			return false
		}
	}
	return true
}

// blockCorrespondence pairs old and new basic blocks one to one. The entry
// blocks always correspond; the remaining pairs are chosen greedily by how
// many matched instructions two blocks share, with ties broken by block
// index so the result is deterministic.
func (z *Zipper) blockCorrespondence() map[*ssa.BasicBlock]*ssa.BasicBlock {
	type blockPair struct{ old, new *ssa.BasicBlock }
	shared := make(map[blockPair]int)
	for o, n := range z.instrMap {
		if o.Block() != nil && n.Block() != nil {
			shared[blockPair{o.Block(), n.Block()}]++
		}
	}
	pairs := make([]blockPair, 0, len(shared))
	for p := range shared {
		pairs = append(pairs, p)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if shared[pairs[i]] != shared[pairs[j]] {
			return shared[pairs[i]] > shared[pairs[j]]
		}
		if pairs[i].old.Index != pairs[j].old.Index {
			return pairs[i].old.Index < pairs[j].old.Index
		}
		return pairs[i].new.Index < pairs[j].new.Index
	})

	corr := make(map[*ssa.BasicBlock]*ssa.BasicBlock)
	taken := make(map[*ssa.BasicBlock]bool)
	if len(z.oldFn.Blocks) > 0 && len(z.newFn.Blocks) > 0 {
		corr[z.oldFn.Blocks[0]] = z.newFn.Blocks[0]
		taken[z.newFn.Blocks[0]] = true
	}
	for _, p := range pairs {
		if _, done := corr[p.old]; done || taken[p.new] {
			continue
		}
		corr[p.old] = p.new
		taken[p.new] = true
	}
	return corr
}

// misplacedPairs returns the matched old instructions whose partner lies in
// a block that does not correspond to theirs, and matched branches (If,
// Jump) whose successors lead to non-corresponding blocks. Either means the
// control flow around otherwise identical operations changed.
func (z *Zipper) misplacedPairs() map[ssa.Instruction]bool {
	corr := z.blockCorrespondence()
	misplaced := make(map[ssa.Instruction]bool)
	for o, n := range z.instrMap {
		ob, nb := o.Block(), n.Block()
		if ob == nil || nb == nil {
			continue
		}
		if corr[ob] != nb {
			misplaced[o] = true
			continue
		}
		switch o.(type) {
		case *ssa.If, *ssa.Jump:
			if len(ob.Succs) != len(nb.Succs) {
				misplaced[o] = true
				continue
			}
			for k, s := range ob.Succs {
				if mapped, ok := corr[s]; ok && mapped != nb.Succs[k] {
					misplaced[o] = true
					break
				}
			}
		}
	}
	return misplaced
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
				sb.WriteString(z.renamer(instr).FuncName(v, nil))
			case *ssa.Builtin:
				sb.WriteString(":builtin:")
				sb.WriteString(v.Name())
			case *ssa.MakeClosure:
				sb.WriteString(":closure")
				if fn, ok := v.Fn.(*ssa.Function); ok {
					sb.WriteString(":")
					sb.WriteString(z.typeString(instr, fn.Signature))
				}
			default:
				if i.Call.Value != nil {
					sb.WriteString(":dynamic:")
					sb.WriteString(z.typeString(instr, i.Call.Value.Type()))
				} else {
					sb.WriteString(":call")
				}
			}
		}
	case *ssa.Alloc:
		sb.WriteString(":")
		sb.WriteString(z.typeString(instr, i.Type()))
	case *ssa.Field:
		sb.WriteString(":field:")
		sb.WriteString(ir.FieldName(i.X, i.Field))
	case *ssa.FieldAddr:
		sb.WriteString(":fieldaddr:")
		sb.WriteString(ir.FieldName(i.X, i.Field))
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

// sameType compares types across the old and new programs. They come from
// separate packages.Load calls, so a package-local named type (a method
// receiver, a parameter of type *T) is a distinct types.Type object on each
// side and never types.Identical to its counterpart. Fall back to comparing
// type strings, rendering each side's own package unqualified so the
// comparison also holds when the two versions were loaded under different
// package paths.
func (z *Zipper) sameType(a, b types.Type) bool {
	if a == nil || b == nil {
		return a == b
	}
	if types.Identical(a, b) {
		return true
	}
	a, b = z.oldTP.Rename(a), z.newTP.Rename(b)
	return types.TypeString(a, localQualifier(z.oldFn)) == types.TypeString(b, localQualifier(z.newFn))
}

// typeString renders t, a type used by instr, with full package paths and
// the type parameters of instr's side by position.
func (z *Zipper) typeString(instr ssa.Instruction, t types.Type) string {
	return types.TypeString(z.renamer(instr).Rename(t), nil)
}

func (z *Zipper) renamer(instr ssa.Instruction) *ir.TypeParamRenamer {
	if instr.Parent() == z.oldFn {
		return z.oldTP
	}
	return z.newTP
}

func localQualifier(fn *ssa.Function) types.Qualifier {
	var own *types.Package
	if fn.Pkg != nil {
		own = fn.Pkg.Pkg
	}
	return func(p *types.Package) string {
		if p == own {
			return ""
		}
		return p.Path()
	}
}
