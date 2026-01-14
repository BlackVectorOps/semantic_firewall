package semanticfw

import (
	"fmt"
	"go/token"
	"go/types"
	"reflect"
	"sort"

	"golang.org/x/tools/go/ssa"
)

// Output from the semantic delta analysis. Shows what instructions were added,
// removed, or matched between two function versions.
type ZipperArtifacts struct {
	OldFunction  string
	NewFunction  string
	MatchedNodes int
	Added        []string
	Removed      []string
	Preserved    bool
}

// Implements the semantic delta analysis algorithm. Walks the use def chains
// of two functions in parallel, aligning equivalent nodes and isolating divergence.
type Zipper struct {
	oldFn *ssa.Function
	newFn *ssa.Function

	policy LiteralPolicy

	oldCanon *Canonicalizer
	newCanon *Canonicalizer

	valMap   map[ssa.Value]ssa.Value
	instrMap map[ssa.Instruction]ssa.Instruction

	revInstrMap map[ssa.Instruction]ssa.Instruction

	queue []valuePair
}

type valuePair struct {
	old ssa.Value
	new ssa.Value
}

// Creates a new analysis session between two function versions.
func NewZipper(oldFn, newFn *ssa.Function, policy LiteralPolicy) (*Zipper, error) {
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
	}, nil
}

// Runs through all four phases of the Zipper algorithm: semantic analysis,
// anchor alignment, forward propagation, and divergence isolation.
func (z *Zipper) ComputeDiff() (*ZipperArtifacts, error) {
	// PHASE 0: Semantic Analysis
	z.oldCanon = AcquireCanonicalizer(z.policy)
	defer ReleaseCanonicalizer(z.oldCanon)
	z.newCanon = AcquireCanonicalizer(z.policy)
	defer ReleaseCanonicalizer(z.newCanon)

	z.oldCanon.analyzeLoops(z.oldFn)
	z.oldCanon.normalizeInductionVariables()
	z.newCanon.analyzeLoops(z.newFn)
	z.newCanon.normalizeInductionVariables()

	// PHASE 1: Anchor Alignment
	if err := z.alignAnchors(); err != nil {
		return nil, err
	}

	// PHASE 2: Forward Propagation
	z.propagate()

	// PHASE 2.5: Scavenge Terminators
	// Match sinks/returns using semantic checks.
	z.matchTerminators()

	// PHASE 3: Divergence Isolation
	return z.isolateDivergence(), nil
}

// Establishes deterministic starting points by mapping parameters and free
// variables between the two functions.
func (z *Zipper) alignAnchors() error {
	// 1. Signature Parity Check
	if len(z.oldFn.Params) != len(z.newFn.Params) {
		return fmt.Errorf("parameter count mismatch: %d vs %d", len(z.oldFn.Params), len(z.newFn.Params))
	}

	// 2. Map Parameters (Entry Anchors)
	for i, pOld := range z.oldFn.Params {
		pNew := z.newFn.Params[i]
		if !types.Identical(pOld.Type(), pNew.Type()) {
			return fmt.Errorf("parameter %d type mismatch: %s vs %s", i, pOld.Type(), pNew.Type())
		}
		z.mapValue(pOld, pNew)
	}

	// 3. Map Free Variables
	if len(z.oldFn.FreeVars) == len(z.newFn.FreeVars) {
		for i, fvOld := range z.oldFn.FreeVars {
			fvNew := z.newFn.FreeVars[i]
			if types.Identical(fvOld.Type(), fvNew.Type()) {
				z.mapValue(fvOld, fvNew)
			}
		}
	}

	// 4. Align Entry Blocks (Handling functions with no params like main/init)
	// Seed the queue by matching constant-only instructions in the entry block.
	z.alignEntryBlock()

	return nil
}

// Matches instructions in the entry block sequentially. Critical for functions
// like main() that have no parameters to serve as anchors.
func (z *Zipper) alignEntryBlock() {
	if len(z.oldFn.Blocks) == 0 || len(z.newFn.Blocks) == 0 {
		return
	}

	// Only process the Entry Block (Index 0)
	// Instructions here are guaranteed to dominate the rest of the function
	bOld := z.oldFn.Blocks[0]
	bNew := z.newFn.Blocks[0]

	// Conservative approach: Match sequentially from the top until divergence.
	// This works because the start of the entry block is a fixed point.
	limit := len(bOld.Instrs)
	if len(bNew.Instrs) < limit {
		limit = len(bNew.Instrs)
	}

	for i := 0; i < limit; i++ {
		iOld := bOld.Instrs[i]
		iNew := bNew.Instrs[i]

		// Skip instructions already mapped (though unlikely in entry block start)
		if _, mapped := z.instrMap[iOld]; mapped {
			continue
		}

		// Check strict equivalence
		if z.areEquivalent(iOld, iNew) {
			z.recordInstrMatch(iOld, iNew)
			if vOld, okOld := iOld.(ssa.Value); okOld {
				if vNew, okNew := iNew.(ssa.Value); okNew {
					z.mapValue(vOld, vNew)
				}
			}
		} else {
			// Stop at first mismatch to avoid false pairings
			break
		}
	}
}

// Identifies and pairs terminators (returns, panics) whose operands match.
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

	// Use matchUsers logic to safely pair them based on operands
	z.matchUsers(oldTerms, newTerms)
}

// Registers a match between values and queues them for propagation.
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

// Traverses use def chains to zip dependent nodes together.
func (z *Zipper) propagate() {
	// Use index-based iteration to avoid repeated slice reallocations
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
	// Clear processed queue to free memory
	z.queue = z.queue[:0]
}

// Limits comparison candidates per fingerprint bucket. Prevents algorithmic DoS
// where malicious inputs with thousands of identical operations could cause O(N*M)
// comparisons. With this limit, worst case becomes O(N * MaxCandidates) which is linear.
const MaxCandidates = 100

// Pairs users of mapped values using structural fingerprints for bucketing.
func (z *Zipper) matchUsers(usersOld, usersNew []ssa.Instruction) {
	// Bucket users by structural fingerprint for efficient lookup.
	newByOp := make(map[string][]ssa.Instruction)
	for _, u := range usersNew {
		if _, mapped := z.revInstrMap[u]; mapped {
			continue
		}
		// Fingerprint excludes register names for stability
		fp := getFingerprint(u)
		// Cap bucket size to prevent quadratic blowup.
		if len(newByOp[fp]) < MaxCandidates {
			newByOp[fp] = append(newByOp[fp], u)
		}
	}

	sortInstrs(usersOld)

	for _, uOld := range usersOld {
		if _, mapped := z.instrMap[uOld]; mapped {
			continue
		}

		fp := getFingerprint(uOld)
		candidates := newByOp[fp] // Only compare against structurally compatible nodes

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
				break // Greedy match found
			}
		}
	}
}

// Checks whether two instructions are semantically isomorphic.
func (z *Zipper) areEquivalent(a, b ssa.Instruction) bool {
	// 1. Structural Identity (Go Type)
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}

	// 2. Value Type Identity (Fix for Alloc(int) vs Alloc(float))
	if vA, ok := a.(ssa.Value); ok {
		vB := b.(ssa.Value)
		if !types.Identical(vA.Type(), vB.Type()) {
			return false
		}
	}

	// 3. Operation-Specific Properties
	if !z.compareOps(a, b) {
		return false
	}

	// 4. Operand Equivalence
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
	// Type equality checks for type-defining instructions.
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
		// Slice operations are structurally identical if types match
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

// Returns true if the given token represents a commutative operation.
func isCommutativeOp(op token.Token) bool {
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

	// Handle commutativity for binary operations.
	if binOp, ok := a.(*ssa.BinOp); ok && isCommutativeOp(binOp.Op) && len(opsA) == 2 {
		if !z.compareOperandPair(opsA[0], opsA[1], opsB[0], opsB[1]) {
			// Try swapped order: A[0]<->B[1], A[1]<->B[0]
			return z.compareOperandPair(opsA[0], opsA[1], opsB[1], opsB[0])
		}
		return true
	}

	for i, ptrA := range opsA {
		// Defensive Check
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

		// Case 1: Value is already mapped
		if mappedB, ok := z.valMap[valA]; ok {
			if mappedB != valB {
				return false
			}
			continue
		}

		// Case 2: Unmapped Operand Handling
		isLinkable := z.isLinkable(valA)

		if isLinkable {
			// If it's a Phi node, we allow unmapped operands (Back-edges).
			if _, isPhi := a.(*ssa.Phi); isPhi {
				// Ensure valB is also linkable.
				if !z.isLinkable(valB) {
					return false
				}
				// Verify types match for unmapped Phi operands.
				if valA.Type() != nil && valB.Type() != nil {
					if !types.Identical(valA.Type(), valB.Type()) {
						return false
					}
				}
				continue
			}
			return false
		}

		// Case 3: Literals
		canonA := z.oldCanon.normalizeOperand(valA, a)
		canonB := z.newCanon.normalizeOperand(valB, b)

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

// Checks if operand pairs match (ptrA0<->ptrB0, ptrA1<->ptrB1).
func (z *Zipper) compareOperandPair(ptrA0, ptrA1, ptrB0, ptrB1 *ssa.Value) bool {
	return z.compareOneOperand(ptrA0, ptrB0) && z.compareOneOperand(ptrA1, ptrB1)
}

// Checks if a single operand pair matches.
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

	// Case 1: Value is already mapped
	if mappedB, ok := z.valMap[valA]; ok {
		return mappedB == valB
	}

	// Case 2: Unmapped linkable values are not allowed in non-Phi context
	if z.isLinkable(valA) {
		return false
	}

	// Case 3: Literals - compare canonical forms
	canonA := z.oldCanon.normalizeOperand(valA, nil)
	canonB := z.newCanon.normalizeOperand(valB, nil)
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
			if z.oldCanon.virtualizedInstrs[instr] {
				continue
			}
			if _, ok := z.instrMap[instr]; !ok {
				r.Removed = append(r.Removed, z.formatInstr(instr))
			}
		}
	}

	for _, b := range z.newFn.Blocks {
		for _, instr := range b.Instrs {
			if z.newCanon.virtualizedInstrs[instr] {
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

// Helper: Sort instructions for deterministic matching using Structural Fingerprints
type instrSorter []ssa.Instruction

func (s instrSorter) Len() int      { return len(s) }
func (s instrSorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s instrSorter) Less(i, j int) bool {
	// Sort by fingerprint instead of volatile register names.
	fi := getFingerprint(s[i])
	fj := getFingerprint(s[j])
	if fi != fj {
		return fi < fj
	}
	// Tie-break with raw string if structure is identical
	return s[i].String() < s[j].String()
}

func getFingerprint(instr ssa.Instruction) string {
	// Generates a signature independent of register allocation.
	// Includes instruction-specific details and call targets to ensure distinct
	// operations fall into different buckets.
	key := fmt.Sprintf("%T", instr)
	switch i := instr.(type) {
	case *ssa.BinOp:
		key += ":" + i.Op.String()
	case *ssa.UnOp:
		key += ":" + i.Op.String()
	case *ssa.Call:
		if i.Call.IsInvoke() {
			key += ":invoke:" + i.Call.Method.Name()
		} else {
			// Include call target to differentiate distinct static calls
			switch v := i.Call.Value.(type) {
			case *ssa.Function:
				key += ":call:" + v.RelString(nil)
			case *ssa.Builtin:
				key += ":builtin:" + v.Name()
			case *ssa.MakeClosure:
				if fn, ok := v.Fn.(*ssa.Function); ok {
					key += ":closure:" + fn.Signature.String()
				} else {
					key += ":closure"
				}
			default:
				// Dynamic call - use type signature for some differentiation
				if i.Call.Value != nil {
					key += ":dynamic:" + i.Call.Value.Type().String()
				} else {
					key += ":call"
				}
			}
		}
	case *ssa.Alloc:
		// Distinguish allocation types (e.g., new(int) vs new(float))
		key += ":" + i.Type().String()
	case *ssa.Field:
		// Distinguish field accesses
		key += fmt.Sprintf(":field:%d", i.Field)
	case *ssa.FieldAddr:
		key += fmt.Sprintf(":fieldaddr:%d", i.Field)
	case *ssa.Index:
		key += ":index"
	case *ssa.IndexAddr:
		key += ":indexaddr"
	case *ssa.Store:
		key += ":store"
	}
	return key
}

func sortInstrs(instrs []ssa.Instruction) {
	sort.Sort(instrSorter(instrs))
}
