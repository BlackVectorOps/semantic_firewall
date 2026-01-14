package semanticfw

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/tools/go/ssa"
)

// Represents an instruction's virtual location after normalization.
type virtualInstr struct {
	instr        ssa.Instruction
	virtualBlock *ssa.BasicBlock
}

// Represents a block's virtual state after normalization.
type virtualBlock struct {
	block        *ssa.BasicBlock
	virtualSuccs [2]*ssa.BasicBlock
	swapped      bool
}

// Manages reusable Canonicalizer instances.
var canonicalizerPool = sync.Pool{
	New: func() interface{} {
		return &Canonicalizer{
			registerMap:          make(map[ssa.Value]string),
			blockMap:             make(map[*ssa.BasicBlock]string),
			virtualInstrs:        make(map[ssa.Instruction]*virtualInstr),
			virtualBlocks:        make(map[*ssa.BasicBlock]*virtualBlock),
			virtualBinOps:        make(map[*ssa.BinOp]token.Token),
			hoistedInstrs:        make(map[ssa.Instruction]bool),
			sunkInstrs:           make(map[ssa.Instruction]bool),
			virtualPhiConstants:  make(map[*ssa.Phi]map[int]string),
			virtualSubstitutions: make(map[ssa.Value]ssa.Value),
			virtualizedInstrs:    make(map[ssa.Instruction]bool),
		}
	},
}

func AcquireCanonicalizer(policy LiteralPolicy) *Canonicalizer {
	c := canonicalizerPool.Get().(*Canonicalizer)
	c.Policy = policy
	c.fullReset()
	return c
}

func ReleaseCanonicalizer(c *Canonicalizer) {
	if c == nil {
		return
	}
	c.fullReset()
	canonicalizerPool.Put(c)
}

// Transforms an SSA function into a deterministic string representation.
type Canonicalizer struct {
	Policy     LiteralPolicy
	StrictMode bool

	loopInfo *LoopInfo // SCEV Analysis Results

	registerMap          map[ssa.Value]string
	blockMap             map[*ssa.BasicBlock]string
	regCounter           int
	output               strings.Builder
	virtualInstrs        map[ssa.Instruction]*virtualInstr
	virtualBlocks        map[*ssa.BasicBlock]*virtualBlock
	virtualBinOps        map[*ssa.BinOp]token.Token
	hoistedInstrs        map[ssa.Instruction]bool
	sunkInstrs           map[ssa.Instruction]bool
	virtualPhiConstants  map[*ssa.Phi]map[int]string
	virtualSubstitutions map[ssa.Value]ssa.Value
	effectiveInstrs      map[*ssa.BasicBlock][]ssa.Instruction

	// Set of instructions masked by SCEV normalization
	virtualizedInstrs map[ssa.Instruction]bool
}

func NewCanonicalizer(policy LiteralPolicy) *Canonicalizer {
	return AcquireCanonicalizer(policy)
}

func (c *Canonicalizer) ApplyVirtualControlFlowFromState(swappedBlocks map[*ssa.BasicBlock]bool, virtualBinOps map[*ssa.BinOp]token.Token) {
	for block := range swappedBlocks {
		if len(block.Succs) == 2 {
			c.virtualBlocks[block] = &virtualBlock{
				block:        block,
				virtualSuccs: [2]*ssa.BasicBlock{block.Succs[1], block.Succs[0]},
				swapped:      true,
			}
		}
	}
	for binOp, op := range virtualBinOps {
		c.virtualBinOps[binOp] = op
	}
}

func (c *Canonicalizer) CanonicalizeFunction(fn *ssa.Function) string {
	if len(fn.Blocks) == 0 {
		return fmt.Sprintf("func%s (external)\n", sanitizeType(fn.Signature))
	}

	c.resetScratch()
	
	// Pre-allocate strings.Builder capacity based on function size
	// Estimate: ~50 bytes per instruction on average
	estimatedSize := 0
	for _, block := range fn.Blocks {
		estimatedSize += len(block.Instrs) * 50
	}
	c.output.Grow(estimatedSize)

	// PHASE 1: Semantic Analysis (Loops & SCEV)
	// We run this before normalization to inform the canonicalization strategy.
	c.analyzeLoops(fn)

	// PHASE 2: Semantic Normalization
	c.hoistInvariantCalls(fn)
	// Integrate SCEV-based Normalization (Section 6.2.1)
	c.normalizeInductionVariables()

	// PHASE 3: Register Naming
	for i, param := range fn.Params {
		c.normalizeValue(param, fmt.Sprintf("p%d", i))
	}
	for i, fv := range fn.FreeVars {
		c.normalizeValue(fv, fmt.Sprintf("fv%d", i))
	}

	// PHASE 4: Deterministic Ordering
	sortedBlocks := c.deterministicTraversal(fn)
	for i, block := range sortedBlocks {
		c.blockMap[block] = fmt.Sprintf("b%d", i)
	}

	c.writeFunctionSignature(fn)

	// PHASE 5: Instruction Processing
	c.reconstructBlockInstructions(fn)
	for _, block := range sortedBlocks {
		if _, exists := c.blockMap[block]; exists {
			c.processBlock(block)
		}
	}

	return c.output.String()
}

func (c *Canonicalizer) analyzeLoops(fn *ssa.Function) {
	// Detect Loops
	c.loopInfo = DetectLoops(fn)
	// Run SCEV Analysis (populates Inductions and TripCounts)
	AnalyzeSCEV(c.loopInfo)
}

// Utilizes SCEV results to rewrite Basic IVs.
// Ref: Section 6.2.1 "Induction Variable Normalization".
// This function now propagates SCEV normalization to derived values, not just
// the root Phi nodes. Any instruction that resolves to an SCEVAddRec is virtualized.
func (c *Canonicalizer) normalizeInductionVariables() {
	if c.loopInfo == nil {
		return
	}

	c.normalizeInductionVariablesRecursive(c.loopInfo.Loops)
}

// Processes loops and their children.
func (c *Canonicalizer) normalizeInductionVariablesRecursive(loops []*Loop) {
	for _, loop := range loops {
		// Process child loops first (bottom-up)
		c.normalizeInductionVariablesRecursive(loop.Children)

		// Step 1: Normalize the root IV Phi nodes
		for phi, iv := range loop.Inductions {
			if iv.Type == IVTypeBasic {
				// We mask the original Phi instruction so it doesn't appear in output.
				c.virtualizedInstrs[phi] = true

				// Register substitution: phi -> {Start, +, Step}
				// The SCEVAddRec implements ssa.Value interface (stubbed in scev.go),
				// allowing it to be stored here and printed by normalizeOperand.
				scev := &SCEVAddRec{Start: iv.Start, Step: iv.Step, Loop: loop}
				c.virtualSubstitutions[phi] = scev
			}
		}

		// Step 2: Propagate SCEV to derived values in the loop body.
		// Iterate through all instructions in the loop and attempt to convert
		// each one to an SCEV. If it resolves to an AddRec, virtualize it.
		for block := range loop.Blocks {
			for _, instr := range block.Instrs {
				// Skip instructions already virtualized (e.g., Phi nodes)
				if c.virtualizedInstrs[instr] {
					continue
				}

				// Only process BinOps that could produce derived IVs
				binOp, ok := instr.(*ssa.BinOp)
				if !ok {
					continue
				}

				// Convert the BinOp to SCEV
				scev := toSCEV(binOp, loop)

				// If it resolves to an AddRec, this is a derived IV expression
				// that should be virtualized for canonical representation
				if addRec, ok := scev.(*SCEVAddRec); ok {
					c.virtualizedInstrs[binOp] = true
					c.virtualSubstitutions[binOp] = addRec
				}
			}
		}
	}
}

func (c *Canonicalizer) reconstructBlockInstructions(fn *ssa.Function) {
	c.effectiveInstrs = make(map[*ssa.BasicBlock][]ssa.Instruction)
	nativeBody := make(map[*ssa.BasicBlock][]ssa.Instruction)
	tailInstrs := make(map[*ssa.BasicBlock][]ssa.Instruction)
	terminators := make(map[*ssa.BasicBlock]ssa.Instruction)

	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			// Skip virtualized instructions (e.g. normalized IV Phis)
			if c.virtualizedInstrs[instr] {
				continue
			}

			targetBlock := c.getVirtualBlock(instr)
			isTerm := isTerminator(instr)

			if isTerm && targetBlock == b {
				terminators[b] = instr
				continue
			}

			isSunk := c.sunkInstrs[instr]
			isMoved := targetBlock != b

			if isSunk || isMoved {
				tailInstrs[targetBlock] = append(tailInstrs[targetBlock], instr)
			} else {
				nativeBody[targetBlock] = append(nativeBody[targetBlock], instr)
			}
		}
	}

	for _, b := range fn.Blocks {
		var combined []ssa.Instruction
		combined = append(combined, nativeBody[b]...)
		combined = append(combined, tailInstrs[b]...)
		if t, ok := terminators[b]; ok {
			combined = append(combined, t)
		}
		c.effectiveInstrs[b] = combined
	}
}

func isTerminator(instr ssa.Instruction) bool {
	switch instr.(type) {
	case *ssa.If, *ssa.Jump, *ssa.Return, *ssa.Panic:
		return true
	}
	return false
}

func (c *Canonicalizer) hoistInvariantCalls(fn *ssa.Function) {
	sccs := c.computeSCCs(fn)

	for _, scc := range sccs {
		if len(scc) == 1 {
			block := scc[0]
			hasSelfLoop := false
			for _, succ := range block.Succs {
				if succ == block {
					hasSelfLoop = true
					break
				}
			}
			if !hasSelfLoop {
				continue
			}
		}

		loopBlocks := make(map[*ssa.BasicBlock]bool)
		for _, b := range scc {
			loopBlocks[b] = true
		}

		var preHeaders []*ssa.BasicBlock
		for _, b := range scc {
			for _, pred := range b.Preds {
				if !loopBlocks[pred] {
					preHeaders = append(preHeaders, pred)
				}
			}
		}

		if len(preHeaders) == 0 {
			if len(fn.Blocks) > 0 && !loopBlocks[fn.Blocks[0]] {
				preHeaders = append(preHeaders, fn.Blocks[0])
			}
		}

		uniquePre := make(map[*ssa.BasicBlock]bool)
		var dedupedPre []*ssa.BasicBlock
		for _, b := range preHeaders {
			if !uniquePre[b] {
				uniquePre[b] = true
				dedupedPre = append(dedupedPre, b)
			}
		}
		preHeaders = dedupedPre

		if len(preHeaders) != 1 {
			continue
		}

		hoistTarget := preHeaders[0]

		for _, b := range scc {
			for _, instr := range b.Instrs {
				call, ok := instr.(*ssa.Call)
				if !ok {
					continue
				}

				if !c.isPureBuiltin(call) {
					continue
				}

				if c.areArgsInvariantLoop(call, loopBlocks) {
					c.hoistedInstrs[call] = true
					c.moveInstrToOtherBlock(call, hoistTarget)
				}
			}
		}
	}
}

func (c *Canonicalizer) computeSCCs(fn *ssa.Function) [][]*ssa.BasicBlock {
	type tarjanState struct {
		index    int
		stack    []*ssa.BasicBlock
		onStack  map[*ssa.BasicBlock]bool
		indices  map[*ssa.BasicBlock]int
		lowLinks map[*ssa.BasicBlock]int
		sccs     [][]*ssa.BasicBlock
	}

	state := &tarjanState{
		onStack:  make(map[*ssa.BasicBlock]bool),
		indices:  make(map[*ssa.BasicBlock]int),
		lowLinks: make(map[*ssa.BasicBlock]int),
	}

	var strongConnect func(v *ssa.BasicBlock)
	strongConnect = func(v *ssa.BasicBlock) {
		state.indices[v] = state.index
		state.lowLinks[v] = state.index
		state.index++
		state.stack = append(state.stack, v)
		state.onStack[v] = true

		for _, w := range v.Succs {
			if _, visited := state.indices[w]; !visited {
				strongConnect(w)
				if state.lowLinks[w] < state.lowLinks[v] {
					state.lowLinks[v] = state.lowLinks[w]
				}
			} else if state.onStack[w] {
				if state.indices[w] < state.lowLinks[v] {
					state.lowLinks[v] = state.indices[w]
				}
			}
		}

		if state.lowLinks[v] == state.indices[v] {
			var component []*ssa.BasicBlock
			for {
				w := state.stack[len(state.stack)-1]
				state.stack = state.stack[:len(state.stack)-1]
				state.onStack[w] = false
				component = append(component, w)
				if w == v {
					break
				}
			}
			state.sccs = append(state.sccs, component)
		}
	}

	for _, block := range fn.Blocks {
		if _, visited := state.indices[block]; !visited {
			strongConnect(block)
		}
	}

	return state.sccs
}

func (c *Canonicalizer) moveInstrToOtherBlock(target ssa.Instruction, dest *ssa.BasicBlock) {
	c.virtualInstrs[target] = &virtualInstr{
		instr:        target,
		virtualBlock: dest,
	}
}

func (c *Canonicalizer) getVirtualBlock(instr ssa.Instruction) *ssa.BasicBlock {
	if vi, ok := c.virtualInstrs[instr]; ok {
		return vi.virtualBlock
	}
	return instr.Block()
}

func (c *Canonicalizer) getVirtualSuccessors(b *ssa.BasicBlock) []*ssa.BasicBlock {
	if b == nil {
		return nil
	}
	if vb, ok := c.virtualBlocks[b]; ok && vb.swapped {
		return []*ssa.BasicBlock{vb.virtualSuccs[0], vb.virtualSuccs[1]}
	}
	return b.Succs
}

func (c *Canonicalizer) getVirtualBinOpToken(binOp *ssa.BinOp) token.Token {
	if virtualOp, ok := c.virtualBinOps[binOp]; ok {
		return virtualOp
	}
	return binOp.Op
}

func (c *Canonicalizer) isPureBuiltin(call *ssa.Call) bool {
	if call.Call.IsInvoke() {
		return false
	}
	builtin, ok := call.Call.Value.(*ssa.Builtin)
	if !ok {
		return false
	}
	name := builtin.Name()
	return name == "len" || name == "cap"
}

// Checks if arguments are invariant relative to the loop.
func (c *Canonicalizer) areArgsInvariantLoop(call *ssa.Call, loopBlocks map[*ssa.BasicBlock]bool) bool {
	for _, arg := range call.Call.Args {
		if _, ok := arg.(*ssa.Const); ok {
			continue
		}
		if _, ok := arg.(*ssa.Global); ok {
			continue
		}
		if _, ok := arg.(*ssa.Parameter); ok {
			continue
		}
		// Captured variables (FreeVars) are also invariant in closure scope.
		if _, ok := arg.(*ssa.FreeVar); ok {
			continue
		}
		// Instructions defined outside the loop are invariant.
		if instr, ok := arg.(ssa.Instruction); ok {
			if instr.Block() != nil && !loopBlocks[instr.Block()] {
				continue
			}
		}
		return false
	}
	return true
}

func (c *Canonicalizer) fullReset() {
	c.resetConfig()
	c.resetScratch()
}

func (c *Canonicalizer) resetConfig() {
	if c.virtualBlocks != nil {
		for k := range c.virtualBlocks {
			delete(c.virtualBlocks, k)
		}
	} else {
		c.virtualBlocks = make(map[*ssa.BasicBlock]*virtualBlock)
	}

	if c.virtualBinOps != nil {
		for k := range c.virtualBinOps {
			delete(c.virtualBinOps, k)
		}
	} else {
		c.virtualBinOps = make(map[*ssa.BinOp]token.Token)
	}
}

func (c *Canonicalizer) resetScratch() {
	if c.registerMap != nil {
		for k := range c.registerMap {
			delete(c.registerMap, k)
		}
	} else {
		c.registerMap = make(map[ssa.Value]string)
	}

	if c.blockMap != nil {
		for k := range c.blockMap {
			delete(c.blockMap, k)
		}
	} else {
		c.blockMap = make(map[*ssa.BasicBlock]string)
	}

	c.regCounter = 0
	c.output.Reset()
	c.loopInfo = nil

	if c.virtualInstrs != nil {
		for k := range c.virtualInstrs {
			delete(c.virtualInstrs, k)
		}
	} else {
		c.virtualInstrs = make(map[ssa.Instruction]*virtualInstr)
	}

	if c.hoistedInstrs != nil {
		for k := range c.hoistedInstrs {
			delete(c.hoistedInstrs, k)
		}
	} else {
		c.hoistedInstrs = make(map[ssa.Instruction]bool)
	}

	if c.sunkInstrs != nil {
		for k := range c.sunkInstrs {
			delete(c.sunkInstrs, k)
		}
	} else {
		c.sunkInstrs = make(map[ssa.Instruction]bool)
	}

	if c.virtualPhiConstants != nil {
		for k := range c.virtualPhiConstants {
			delete(c.virtualPhiConstants, k)
		}
	} else {
		c.virtualPhiConstants = make(map[*ssa.Phi]map[int]string)
	}

	if c.virtualSubstitutions != nil {
		for k := range c.virtualSubstitutions {
			delete(c.virtualSubstitutions, k)
		}
	} else {
		c.virtualSubstitutions = make(map[ssa.Value]ssa.Value)
	}

	if c.virtualizedInstrs != nil {
		for k := range c.virtualizedInstrs {
			delete(c.virtualizedInstrs, k)
		}
	} else {
		c.virtualizedInstrs = make(map[ssa.Instruction]bool)
	}

	c.effectiveInstrs = nil
}

func (c *Canonicalizer) normalizeValue(v ssa.Value, preferredName ...string) string {
	if name, exists := c.registerMap[v]; exists {
		return name
	}
	var name string
	if len(preferredName) > 0 {
		name = preferredName[0]
	} else {
		name = fmt.Sprintf("v%d", c.regCounter)
		c.regCounter++
	}
	c.registerMap[v] = name
	return name
}

// Limits recursion depth in SCEV renaming to prevent stack overflow. A depth of
// 100 is sufficient for legitimate nested expressions while preventing malicious
// deeply nested chains (e.g., v1 = v2, v2 = v3, ... v10000 = C) or exponential
// "Billion Laughs" expansion attacks (e.g., A -> {B, +, B}).
const MaxRenamerDepth = 100

// Returns a Renamer function that maps SSA values to their canonical names.
// Implements cycle detection and depth limiting to prevent stack overflow
// and expansion attacks. The 'stack' map tracks values in the recursion chain.
func (c *Canonicalizer) renamerFunc() Renamer {
	stack := make(map[ssa.Value]bool)
	depth := 0

	var renamer Renamer
	renamer = func(v ssa.Value) string {
		// 1. Check depth limit (Defense against Stack Overflow and Billion Laughs)
		if depth >= MaxRenamerDepth {
			return "<depth-limit>"
		}
		depth++
		defer func() { depth-- }()

		// 2. Check for recursion cycles (Defense against infinite loops)
		if stack[v] {
			return "<cycle>"
		}
		stack[v] = true
		defer delete(stack, v)

		// 3. Iterative Resolution of Substitutions
		visited := make(map[ssa.Value]bool)
		current := v

		for {
			if visited[current] {
				break
			}
			visited[current] = true

			sub, ok := c.virtualSubstitutions[current]
			if !ok {
				break
			}

			// If the substitution is itself an SCEV, stringify it canonically.
			// This call recurses back into renamer(), guarded by 'stack' and 'depth'.
			if scev, isScev := sub.(SCEV); isScev {
				return scev.StringWithRenamer(renamer)
			}

			current = sub
		}

		return c.normalizeValue(current)
	}
	return renamer
}

func (c *Canonicalizer) deterministicTraversal(fn *ssa.Function) []*ssa.BasicBlock {
	var sortedBlocks []*ssa.BasicBlock
	if len(fn.Blocks) == 0 {
		return sortedBlocks
	}
	entryBlock := fn.Blocks[0]
	if entryBlock == nil {
		return sortedBlocks
	}

	visited := make(map[*ssa.BasicBlock]bool)
	stack := []*ssa.BasicBlock{entryBlock}

	for len(stack) > 0 {
		block := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if visited[block] {
			continue
		}
		visited[block] = true
		sortedBlocks = append(sortedBlocks, block)

		succs := c.getVirtualSuccessors(block)
		if len(succs) == 2 {
			stack = append(stack, succs[1])
			stack = append(stack, succs[0])
		} else {
			for i := len(succs) - 1; i >= 0; i-- {
				stack = append(stack, succs[i])
			}
		}
	}
	return sortedBlocks
}

func (c *Canonicalizer) writeFunctionSignature(fn *ssa.Function) {
	c.output.WriteString("func(")
	for i, p := range fn.Params {
		if i > 0 {
			c.output.WriteString(", ")
		}
		c.output.WriteString(fmt.Sprintf("%s: %s", c.registerMap[p], sanitizeType(p.Type())))
	}
	c.output.WriteString(")")
	sig := fn.Signature
	if sig.Results().Len() > 0 {
		c.output.WriteString(" -> (")
		for i := 0; i < sig.Results().Len(); i++ {
			if i > 0 {
				c.output.WriteString(", ")
			}
			c.output.WriteString(sanitizeType(sig.Results().At(i).Type()))
		}
		c.output.WriteString(")")
	}
	c.output.WriteString("\n")
}

func (c *Canonicalizer) processBlock(block *ssa.BasicBlock) {
	c.output.WriteString(c.blockMap[block] + ":\n")

	// Inject Semantic Analysis Results (Section 6.2.2)
	// We check if this block is a Loop Header and print TripCounts.
	// IV definitions are not printed because SCEV normalization propagates to
	// derived values and we don't want fingerprint divergence.
	if c.loopInfo != nil {
		if loop, ok := c.loopInfo.LoopMap[block]; ok {
			c.output.WriteString("  ; LoopHeader")
			if loop.TripCount != nil {
				c.output.WriteString(fmt.Sprintf(" TripCount: %s", loop.TripCount.String()))
			}
			c.output.WriteString("\n")
		}
	}

	instrs := c.effectiveInstrs[block]
	for _, instr := range instrs {
		c.processInstruction(instr)
	}
}

func isCommutative(instr *ssa.BinOp) bool {
	switch instr.Op {
	case token.ADD:
		if basic, ok := instr.X.Type().Underlying().(*types.Basic); ok {
			if (basic.Info()&types.IsInteger) != 0 ||
				(basic.Info()&types.IsFloat) != 0 ||
				(basic.Info()&types.IsComplex) != 0 {
				return true
			}
		}
		return false
	case token.MUL, token.EQL, token.NEQ, token.AND, token.OR, token.XOR:
		return true
	default:
		return false
	}
}

func (c *Canonicalizer) processInstruction(instr ssa.Instruction) {
	var rhs strings.Builder
	val, isValue := instr.(ssa.Value)
	isControlFlow := false

	switch i := instr.(type) {
	case *ssa.Call:
		rhs.WriteString("Call ")
		c.writeCallCommon(&rhs, &i.Call, instr)
	case *ssa.BinOp:
		normX := c.normalizeOperand(i.X, instr)
		normY := c.normalizeOperand(i.Y, instr)
		op := c.getVirtualBinOpToken(i)
		if isCommutative(i) && normX > normY {
			rhs.WriteString(fmt.Sprintf("BinOp %s, %s, %s", op.String(), normY, normX))
		} else {
			rhs.WriteString(fmt.Sprintf("BinOp %s, %s, %s", op.String(), normX, normY))
		}
	case *ssa.UnOp:
		rhs.WriteString(fmt.Sprintf("UnOp %s, %s", i.Op.String(), c.normalizeOperand(i.X, instr)))
		if i.CommaOk {
			rhs.WriteString(", CommaOk")
		}
	case *ssa.Phi:
		c.writePhi(&rhs, i, instr)
	case *ssa.Alloc:
		rhs.WriteString("Alloca ")
		handled := false
		if ptrType, ok := i.Type().Underlying().(*types.Pointer); ok {
			elemType := ptrType.Elem()
			if arrType, ok := elemType.Underlying().(*types.Array); ok {
				length := arrType.Len()
				typeRep := sanitizeType(elemType)
				if length >= 0 {
					lenConst := ssa.NewConst(constant.MakeInt64(length), types.Typ[types.Int])
					if c.Policy.ShouldAbstract(lenConst, instr) {
						typeRep = fmt.Sprintf("[<len_literal>]%s", sanitizeType(arrType.Elem()))
					}
				}
				rhs.WriteString(typeRep)
				handled = true
			} else {
				rhs.WriteString(sanitizeType(elemType))
				handled = true
			}
		}
		if !handled {
			rhs.WriteString(sanitizeType(i.Type().Underlying()))
		}
	case *ssa.Store:
		rhs.WriteString(fmt.Sprintf("Store %s, %s", c.normalizeOperand(i.Addr, instr), c.normalizeOperand(i.Val, instr)))
	case *ssa.If:
		isControlFlow = true
		succs := c.getVirtualSuccessors(i.Block())
		rhs.WriteString(fmt.Sprintf("If %s, %s, %s", c.normalizeOperand(i.Cond, instr), c.blockMap[succs[0]], c.blockMap[succs[1]]))
	case *ssa.Jump:
		isControlFlow = true
		if len(i.Block().Succs) > 0 {
			rhs.WriteString(fmt.Sprintf("Jump %s", c.blockMap[i.Block().Succs[0]]))
		} else {
			rhs.WriteString("Jump <invalid>")
		}
	case *ssa.Return:
		isControlFlow = true
		rhs.WriteString("Return")
		for j, res := range i.Results {
			if j > 0 {
				rhs.WriteString(",")
			}
			rhs.WriteString(" " + c.normalizeOperand(res, instr))
		}
	case *ssa.IndexAddr:
		rhs.WriteString(fmt.Sprintf("IndexAddr %s, %s", c.normalizeOperand(i.X, instr), c.normalizeOperand(i.Index, instr)))
	case *ssa.Index:
		rhs.WriteString(fmt.Sprintf("Index %s, %s", c.normalizeOperand(i.X, instr), c.normalizeOperand(i.Index, instr)))
	case *ssa.Select:
		c.writeSelect(&rhs, i, instr)
	case *ssa.Range:
		rhs.WriteString(fmt.Sprintf("Range %s", c.normalizeOperand(i.X, instr)))
	case *ssa.Next:
		rhs.WriteString(fmt.Sprintf("Next %s", c.normalizeOperand(i.Iter, instr)))
	case *ssa.Extract:
		rhs.WriteString(fmt.Sprintf("Extract %s, %d", c.normalizeOperand(i.Tuple, instr), i.Index))
	case *ssa.Slice:
		rhs.WriteString(fmt.Sprintf("Slice %s", c.normalizeOperand(i.X, instr)))
		if i.Low != nil {
			rhs.WriteString(fmt.Sprintf(", Low:%s", c.normalizeOperand(i.Low, instr)))
		}
		if i.High != nil {
			rhs.WriteString(fmt.Sprintf(", High:%s", c.normalizeOperand(i.High, instr)))
		}
		if i.Max != nil {
			rhs.WriteString(fmt.Sprintf(", Max:%s", c.normalizeOperand(i.Max, instr)))
		}
	case *ssa.MakeSlice:
		rhs.WriteString(fmt.Sprintf("MakeSlice %s, Len:%s, Cap:%s", sanitizeType(i.Type()), c.normalizeOperand(i.Len, instr), c.normalizeOperand(i.Cap, instr)))
	case *ssa.MakeMap:
		rhs.WriteString(fmt.Sprintf("MakeMap %s", sanitizeType(i.Type())))
		if i.Reserve != nil {
			rhs.WriteString(fmt.Sprintf(", Reserve:%s", c.normalizeOperand(i.Reserve, instr)))
		}
	case *ssa.MapUpdate:
		rhs.WriteString(fmt.Sprintf("MapUpdate %s, Key:%s, Val:%s", c.normalizeOperand(i.Map, instr), c.normalizeOperand(i.Key, instr), c.normalizeOperand(i.Value, instr)))
	case *ssa.Lookup:
		rhs.WriteString(fmt.Sprintf("Lookup %s, Key:%s", c.normalizeOperand(i.X, instr), c.normalizeOperand(i.Index, instr)))
		if i.CommaOk {
			rhs.WriteString(", CommaOk")
		}
	case *ssa.TypeAssert:
		rhs.WriteString(fmt.Sprintf("TypeAssert %s, AssertedType:%s", c.normalizeOperand(i.X, instr), sanitizeType(i.AssertedType)))
		if i.CommaOk {
			rhs.WriteString(", CommaOk")
		}
	case *ssa.MakeInterface:
		rhs.WriteString(fmt.Sprintf("MakeInterface %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.ChangeType:
		rhs.WriteString(fmt.Sprintf("ChangeType %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.Convert:
		rhs.WriteString(fmt.Sprintf("Convert %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.Go:
		rhs.WriteString("Go ")
		c.writeCallCommon(&rhs, &i.Call, instr)
	case *ssa.Defer:
		rhs.WriteString("Defer ")
		c.writeCallCommon(&rhs, &i.Call, instr)
	case *ssa.RunDefers:
		rhs.WriteString("RunDefers")
	case *ssa.Panic:
		rhs.WriteString(fmt.Sprintf("Panic %s", c.normalizeOperand(i.X, instr)))
	case *ssa.MakeClosure:
		rhs.WriteString(fmt.Sprintf("MakeClosure %s", c.normalizeOperand(i.Fn, instr)))
		if len(i.Bindings) > 0 {
			rhs.WriteString(" [")
			for j, binding := range i.Bindings {
				if j > 0 {
					rhs.WriteString(", ")
				}
				rhs.WriteString(c.normalizeOperand(binding, instr))
			}
			rhs.WriteString("]")
		}
	case *ssa.FieldAddr:
		rhs.WriteString(fmt.Sprintf("FieldAddr %s, field(%d)", c.normalizeOperand(i.X, instr), i.Field))
	case *ssa.Field:
		rhs.WriteString(fmt.Sprintf("Field %s, field(%d)", c.normalizeOperand(i.X, instr), i.Field))
	case *ssa.Send:
		rhs.WriteString(fmt.Sprintf("Send %s, %s", c.normalizeOperand(i.Chan, instr), c.normalizeOperand(i.X, instr)))
	case *ssa.MakeChan:
		rhs.WriteString(fmt.Sprintf("MakeChan %s, Size:%s", sanitizeType(i.Type()), c.normalizeOperand(i.Size, instr)))
	case *ssa.ChangeInterface:
		rhs.WriteString(fmt.Sprintf("ChangeInterface %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.SliceToArrayPointer:
		rhs.WriteString(fmt.Sprintf("SliceToArrayPointer %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.MultiConvert:
		rhs.WriteString(fmt.Sprintf("MultiConvert %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.DebugRef:
		return

	default:
		if c.StrictMode {
			panic(fmt.Sprintf("STRICT MODE: Unhandled SSA instruction %T", instr))
		}
		rhs.WriteString(fmt.Sprintf("UnhandledInstr<%T>", instr))
	}

	c.output.WriteString("  ")
	if isValue && !isControlFlow {
		isVoid := val.Type() == nil
		if !isVoid {
			if t, ok := val.Type().(*types.Tuple); ok && t.Len() == 0 {
				isVoid = true
			}
		}
		if !isVoid {
			name := c.normalizeValue(val)
			c.output.WriteString(fmt.Sprintf("%s = ", name))
		}
	}
	c.output.WriteString(rhs.String() + "\n")
}

func (c *Canonicalizer) writeSelect(w *strings.Builder, i *ssa.Select, context ssa.Instruction) {
	w.WriteString("Select")
	if i.Blocking {
		w.WriteString(" [blocking]")
	} else {
		w.WriteString(" [non-blocking]")
	}

	type selectState struct {
		dir         string
		chanRepr    string
		sendValRepr string
	}

	var states []selectState
	if !i.Blocking {
		states = append(states, selectState{dir: "<-", chanRepr: "<default>"})
	}

	for _, state := range i.States {
		dirStr := "?"
		switch state.Dir {
		case types.SendOnly:
			dirStr = "->"
		case types.RecvOnly:
			dirStr = "<-"
		}

		s := selectState{dir: dirStr}
		if state.Chan != nil {
			s.chanRepr = c.normalizeOperand(state.Chan, context)
		} else {
			s.chanRepr = "<nil_chan>"
		}

		if state.Send != nil {
			s.sendValRepr = c.normalizeOperand(state.Send, context)
		}
		states = append(states, s)
	}

	sort.SliceStable(states, func(a, b int) bool {
		if states[a].chanRepr != states[b].chanRepr {
			return states[a].chanRepr < states[b].chanRepr
		}
		return states[a].dir < states[b].dir
	})

	for _, state := range states {
		w.WriteString(fmt.Sprintf(" (%s %s", state.dir, state.chanRepr))
		if state.sendValRepr != "" {
			w.WriteString(fmt.Sprintf(" <- %s", state.sendValRepr))
		}
		w.WriteString(")")
	}
}

func (c *Canonicalizer) writePhi(w *strings.Builder, i *ssa.Phi, instr ssa.Instruction) {
	w.WriteString("Phi")
	type edge struct {
		predID    string
		predIndex int
		value     string
	}
	edges := make([]edge, 0, len(i.Edges))
	preds := i.Block().Preds
	for j, val := range i.Edges {
		// Defensive check: ensure Preds and Edges have matching lengths.
		// In well-formed SSA they should match, but we guard against edge cases.
		if j >= len(preds) {
			break
		}
		predBlock := preds[j]
		predID := c.blockMap[predBlock]
		// Skip unmapped blocks and validate predID format before parsing
		if predID == "" || len(predID) < 2 {
			continue
		}
		idx, err := strconv.Atoi(predID[1:])
		if err != nil {
			// Malformed block ID; skip this edge to prevent panic
			continue
		}

		// Check for virtual constant replacement for this Phi edge.
		valStr := c.normalizeOperand(val, instr)
		if overrides, ok := c.virtualPhiConstants[i]; ok {
			if ov, ok := overrides[j]; ok {
				valStr = ov
			}
		}

		edges = append(edges, edge{predID: predID, predIndex: idx, value: valStr})
	}

	sort.SliceStable(edges, func(a, b int) bool {
		return edges[a].predIndex < edges[b].predIndex
	})
	for _, e := range edges {
		w.WriteString(fmt.Sprintf(" [%s: %s]", e.predID, e.value))
	}
}

func (c *Canonicalizer) writeCallCommon(w *strings.Builder, common *ssa.CallCommon, context ssa.Instruction) {
	if common.IsInvoke() {
		w.WriteString("Invoke " + c.normalizeOperand(common.Value, context) + "." + common.Method.Name())
	} else {
		w.WriteString(c.normalizeOperand(common.Value, context))
	}
	w.WriteString("(")
	for i, arg := range common.Args {
		if i > 0 {
			w.WriteString(", ")
		}
		w.WriteString(c.normalizeOperand(arg, context))
	}
	w.WriteString(")")
}

func (c *Canonicalizer) normalizeOperand(v ssa.Value, context ssa.Instruction) string {
	// Resolves transitive substitutions by iterating until a steady state is found.
	// We iterate to find the final replaced value (e.g., A -> B -> C).
	// Use cycle detection to prevent infinite loops in malformed graphs.
	visited := make(map[ssa.Value]bool)
	for {
		if visited[v] {
			// Cycle detected; stop resolution to prevent infinite loop
			break
		}
		visited[v] = true

		sub, ok := c.virtualSubstitutions[v]
		if !ok {
			break
		}

		// Check if the replacement value (sub) IS the instruction currently being printed (context).
		// If they are the same, we must NOT substitute.
		// Doing so would create a self-referential Phi node (e.g., v3 = Phi [..., v3]).
		shouldSubstitute := true
		if subInstr, isInstr := sub.(ssa.Instruction); isInstr {
			if subInstr == context {
				shouldSubstitute = false
			}
		}

		if shouldSubstitute {
			v = sub
		} else {
			break
		}
	}

	switch operand := v.(type) {
	case SCEV:
		// If it resolved to an SCEV object, print it using canonical names.
		// CRITICAL: We must use StringWithRenamer to ensure determinism.
		// Without this, raw SSA names (t0, t1) would leak into the output,
		// causing semantically identical functions with different register
		// allocations to produce different fingerprints.
		return operand.StringWithRenamer(c.renamerFunc())
	case *ssa.Const:
		if c.Policy.ShouldAbstract(operand, context) {
			return fmt.Sprintf("<%s_literal>", sanitizeType(operand.Type()))
		}
		if operand.Value == nil {
			return fmt.Sprintf("const(%s:nil)", sanitizeType(operand.Type()))
		}
		// Sanitize string literals using %q to prevent injection.
		if operand.Value.Kind() == constant.String {
			return fmt.Sprintf("const(%q)", constant.StringVal(operand.Value))
		}
		return fmt.Sprintf("const(%s)", operand.Value.ExactString())
	case *ssa.Global:
		// Include package path and variable name for semantic precision.
		pkgPath := ""
		if operand.Pkg != nil && operand.Pkg.Pkg != nil {
			pkgPath = operand.Pkg.Pkg.Path()
		}
		return fmt.Sprintf("<global:%s.%s:%s>", pkgPath, operand.Name(), sanitizeType(operand.Type()))
	case *ssa.Builtin:
		return fmt.Sprintf("<builtin:%s>", operand.Name())
	case *ssa.Function:
		if name, exists := c.registerMap[v]; exists {
			return name
		}
		return fmt.Sprintf("<func_ref:%s:%s>", operand.Name(), sanitizeType(operand.Signature))
	default:
		return c.normalizeValue(v)
	}
}

func packageQualifier(p *types.Package) string {
	if p != nil {
		return p.Path()
	}
	return ""
}

func sanitizeType(t types.Type) string {
	if t == nil {
		return "<nil_type>"
	}

	var res string
	if sig, ok := t.(*types.Signature); ok {
		var params []string
		for i := 0; i < sig.Params().Len(); i++ {
			paramType := sig.Params().At(i).Type()
			if sig.Variadic() && i == sig.Params().Len()-1 {
				if slice, ok := paramType.(*types.Slice); ok {
					elemStr := types.TypeString(slice.Elem(), packageQualifier)
					params = append(params, "..."+elemStr)
					continue
				}
			}
			params = append(params, sanitizeType(paramType))
		}

		var results []string
		for i := 0; i < sig.Results().Len(); i++ {
			results = append(results, sanitizeType(sig.Results().At(i).Type()))
		}

		resStr := ""
		if len(results) > 0 {
			resStr = " (" + strings.Join(results, ", ") + ")"
		}

		res = fmt.Sprintf("func(%s)%s", strings.Join(params, ", "), resStr)
	} else {
		res = types.TypeString(t, packageQualifier)
	}

	// Sanitize newlines to prevent IR injection via struct tags.
	return strings.ReplaceAll(res, "\n", " ")
}
