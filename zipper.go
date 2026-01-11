package semanticfw

import (
	"fmt"
	"go/types"
	"reflect"
	"sort"

	"golang.org/x/tools/go/ssa"
)

// ZipperArtifacts encapsulates the results of the semantic delta analysis.
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

// NewZipper creates a new analysis session.
func NewZipper(oldFn, newFn *ssa.Function, policy LiteralPolicy) (*Zipper, error) {
	// SECURITY: Input validation prevents panic on nil inputs
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

// ComputeDiff executes the Zipper Algorithm Phases.
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
	// BUG FIX: Explicitly match sinks/returns here using semantic checks
	// instead of blind index matching in the anchor phase.
	z.matchTerminators()

	// PHASE 3: Divergence Isolation
	return z.isolateDivergence(), nil
}

// alignAnchors establishes deterministic starting points.
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

	// NOTE: mapReturns removed. Returns are handled in matchTerminators.

	return nil
}

// matchTerminators identifies and pairs terminators (returns, panics)
// whose operands are strictly equivalent.
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

// mapValue registers a match between values and schedules propagation.
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

// propagate traverses Use-Def chains to zip dependent nodes.
func (z *Zipper) propagate() {
	for len(z.queue) > 0 {
		curr := z.queue[0]
		z.queue = z.queue[1:]

		refsOldPtr := curr.old.Referrers()
		refsNewPtr := curr.new.Referrers()

		if refsOldPtr == nil || refsNewPtr == nil {
			continue
		}

		z.matchUsers(*refsOldPtr, *refsNewPtr)
	}
}

// matchUsers attempts to pair users of mapped values.
func (z *Zipper) matchUsers(usersOld, usersNew []ssa.Instruction) {
	// SECURITY FIX: Bucket users by Structural Fingerprint to prevent O(N*M) DoS
	// on high-fanout values.
	newByOp := make(map[string][]ssa.Instruction)
	for _, u := range usersNew {
		if _, mapped := z.revInstrMap[u]; mapped {
			continue
		}
		// Fingerprint excludes register names for stability
		fp := getFingerprint(u)
		newByOp[fp] = append(newByOp[fp], u)
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

// areEquivalent checks if two instructions are semantically isomorphic.
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
	// BUG FIX: Add missing semantic checks
	case *ssa.Alloc:
		iB := b.(*ssa.Alloc)
		return iA.Heap == iB.Heap
	case *ssa.Extract:
		iB := b.(*ssa.Extract)
		return iA.Index == iB.Index
	case *ssa.Select:
		iB := b.(*ssa.Select)
		return iA.Blocking == iB.Blocking
	}
	return true
}

func (z *Zipper) compareOperands(a, b ssa.Instruction) bool {
	opsA := a.Operands(nil)
	opsB := b.Operands(nil)

	if len(opsA) != len(opsB) {
		return false
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
				// SECURITY FIX: Ensure valB is ALSO linkable.
				// Do not allow matching a dynamic variable with a constant.
				if z.isLinkable(valB) {
					continue
				}
				return false
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
	// FIX: Sort by fingerprint (Type+Op) instead of volatile register names.
	fi := getFingerprint(s[i])
	fj := getFingerprint(s[j])
	if fi != fj {
		return fi < fj
	}
	// Tie-break with raw string if structure is identical
	return s[i].String() < s[j].String()
}

func getFingerprint(instr ssa.Instruction) string {
	// Generates a signature independent of register allocation
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
			key += ":call"
		}
	}
	return key
}

func sortInstrs(instrs []ssa.Instruction) {
	sort.Sort(instrSorter(instrs))
}
