package ir

import (
	"bytes"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/loop"
	"golang.org/x/tools/go/ssa"
)

// MaxLoopAnalysisDepth prevents stack overflow attacks from deeply nested loops during IV normalization.
const MaxLoopAnalysisDepth = 64

var canonicalizerPool = sync.Pool{
	New: func() any { return new(Canonicalizer) },
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

type Canonicalizer struct {
	Policy     LiteralPolicy
	StrictMode bool

	loopInfo *loop.LoopInfo

	registerMap map[ssa.Value]string
	blockMap    map[*ssa.BasicBlock]string
	regCounter  int
	output      strings.Builder
	// scratch holds one instruction's rendering until its result register
	// is named, which happens after its operands are. A bytes.Buffer keeps
	// its storage across Reset; a strings.Builder would reallocate it for
	// every instruction.
	scratch bytes.Buffer
	// virtualInstrs maps a moved instruction to the block it renders in;
	// virtualBlocks maps a block whose branches are swapped to its
	// successors in rendering order.
	virtualInstrs        map[ssa.Instruction]*ssa.BasicBlock
	virtualBlocks        map[*ssa.BasicBlock][]*ssa.BasicBlock
	virtualBinOps        map[*ssa.BinOp]token.Token
	hoistedInstrs        map[ssa.Instruction]bool
	virtualSubstitutions map[ssa.Value]ssa.Value
	// effectiveInstrs is each block's instructions in rendering order,
	// indexed by ssa.BasicBlock.Index.
	effectiveInstrs   [][]ssa.Instruction
	VirtualizedInstrs map[ssa.Instruction]bool

	// renamer renders SCEV operands; built once, it is reentrant and
	// returns to its initial state after every top-level call.
	renamer loop.Renamer

	// typeStrings caches sanitizeType for the function being canonicalized:
	// its result depends only on the type, ownPkg and tparams.
	typeStrings map[types.Type]string

	// ownPkg is the package of the function being canonicalized. Names from
	// it are rendered unqualified so two versions of a function loaded under
	// different package paths still compare equal; names from every other
	// package carry their import path.
	ownPkg *types.Package

	// tparams renders the type parameters in scope in the function being
	// canonicalized by position, so renaming one does not change its form.
	tparams *TypeParamRenamer

	// selectCasePerm and selectRecvPerm map a Select's original case index
	// (and receive-case ordinal) to its position in the sorted rendering, so
	// the comparisons and extracts that bind each case to its body follow the
	// case through the sort.
	selectCasePerm map[*ssa.Select][]int
	selectRecvPerm map[*ssa.Select][]int
}

func NewCanonicalizer(policy LiteralPolicy) *Canonicalizer {
	return AcquireCanonicalizer(policy)
}

func (c *Canonicalizer) ApplyVirtualControlFlowFromState(swappedBlocks map[*ssa.BasicBlock]bool, virtualBinOps map[*ssa.BinOp]token.Token) {
	c.initMaps()
	for block := range swappedBlocks {
		if len(block.Succs) == 2 {
			c.virtualBlocks[block] = []*ssa.BasicBlock{block.Succs[1], block.Succs[0]}
		}
	}
	for binOp, op := range virtualBinOps {
		c.virtualBinOps[binOp] = op
	}
}

func (c *Canonicalizer) CanonicalizeFunction(fn *ssa.Function) string {
	if len(fn.Blocks) == 0 {
		return fmt.Sprintf("func%s (external)\n", sanitizeTypeWith(fn.Signature, packageQualifier))
	}

	c.resetScratch()
	estimatedSize := 0
	for _, block := range fn.Blocks {
		estimatedSize += len(block.Instrs) * 50
	}
	c.output.Grow(estimatedSize)

	// Normalize parameters first to ensure they receive reserved names (p0, p1...)
	// before any analysis passes (like SCEV) potentially reference them.
	for i, param := range fn.Params {
		c.normalizeValue(param, "p"+strconv.Itoa(i))
	}
	for i, fv := range fn.FreeVars {
		c.normalizeValue(fv, "fv"+strconv.Itoa(i))
	}

	c.AnalyzeLoops(fn)
	c.hoistInvariantCalls(fn)
	c.NormalizeInductionVariables()

	// Blocks the traversal does not reach follow it in index order.
	// fn.Blocks is in index order: Blocks[i].Index == i.
	sortedBlocks := c.deterministicTraversal(fn)
	reached := make([]bool, len(fn.Blocks))
	for _, b := range sortedBlocks {
		reached[b.Index] = true
	}
	for _, b := range fn.Blocks {
		if !reached[b.Index] {
			sortedBlocks = append(sortedBlocks, b)
		}
	}

	for i, block := range sortedBlocks {
		c.blockMap[block] = "b" + strconv.Itoa(i)
	}

	c.writeFunctionSignature(fn)
	c.reconstructBlockInstructions(fn)
	for _, block := range sortedBlocks {
		c.processBlock(block)
	}

	return c.output.String()
}

func (c *Canonicalizer) AnalyzeLoops(fn *ssa.Function) {
	c.setOwnPackage(fn)
	if len(fn.Blocks) == 0 {
		return
	}
	c.loopInfo = loop.DetectLoops(fn)
	loop.AnalyzeSCEV(c.loopInfo)
}

func (c *Canonicalizer) setOwnPackage(fn *ssa.Function) {
	c.initMaps()
	c.ownPkg = nil
	if fn.Pkg != nil {
		c.ownPkg = fn.Pkg.Pkg
	}
	c.tparams = NewTypeParamRenamer(fn)
	clear(c.typeStrings)
}

// qualifier renders the canonicalized function's own package unqualified and
// every other package by import path.
func (c *Canonicalizer) qualifier(p *types.Package) string {
	if p == nil || p == c.ownPkg {
		return ""
	}
	return p.Path()
}

func (c *Canonicalizer) NormalizeInductionVariables() {
	if c.loopInfo == nil {
		return
	}
	c.normalizeInductionVariablesRecursive(c.loopInfo.Loops, 0)
}

func (c *Canonicalizer) normalizeInductionVariablesRecursive(loops []*loop.Loop, depth int) {
	if depth >= MaxLoopAnalysisDepth {
		return
	}
	for _, l := range loops {
		c.normalizeInductionVariablesRecursive(l.Children, depth+1)

		for phi, iv := range l.Inductions {
			if iv.Type == loop.IVTypeBasic {
				c.VirtualizedInstrs[phi] = true
				scev := &loop.SCEVAddRec{Start: iv.Start, Step: iv.Step, Loop: l, IntType: phi.Type()}
				c.virtualSubstitutions[phi] = scev
			}
		}

		for block := range l.Blocks {
			for _, instr := range block.Instrs {
				if c.VirtualizedInstrs[instr] {
					continue
				}
				binOp, ok := instr.(*ssa.BinOp)
				if !ok {
					continue
				}
				scev := loop.ToSCEV(binOp, l)
				if addRec, ok := scev.(*loop.SCEVAddRec); ok {
					typed := *addRec
					typed.IntType = binOp.Type()
					c.VirtualizedInstrs[binOp] = true
					c.virtualSubstitutions[binOp] = &typed
				}
			}
		}
	}
}

// reconstructBlockInstructions orders each block's instructions for
// rendering: its phis, its own instructions, the instructions hoisted into
// it (in source block and instruction order, which keeps a hoisted call
// after the hoisted calls from its own block that it depends on), then its
// terminator. Virtualized instructions are left out.
func (c *Canonicalizer) reconstructBlockInstructions(fn *ssa.Function) {
	n := len(fn.Blocks)
	own := make([][]ssa.Instruction, n)
	tails := make([][]ssa.Instruction, n)
	terms := make([]ssa.Instruction, n)
	for _, b := range fn.Blocks {
		own[b.Index] = make([]ssa.Instruction, 0, len(b.Instrs))
		for _, instr := range b.Instrs {
			if c.VirtualizedInstrs[instr] {
				continue
			}
			target := c.getVirtualBlock(instr)
			switch {
			case target != b || c.hoistedInstrs[instr]:
				tails[target.Index] = append(tails[target.Index], instr)
			case isTerminator(instr):
				terms[b.Index] = instr
			default:
				// SSA puts a block's phis first, so they lead.
				own[b.Index] = append(own[b.Index], instr)
			}
		}
	}

	c.effectiveInstrs = make([][]ssa.Instruction, n)
	for i := range own {
		instrs := append(own[i], tails[i]...)
		if terms[i] != nil {
			instrs = append(instrs, terms[i])
		}
		c.effectiveInstrs[i] = instrs
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

// computeSCCs returns fn's strongly connected components (Tarjan). Per-block
// state is indexed by ssa.BasicBlock.Index; an order of -1 means unvisited.
func (c *Canonicalizer) computeSCCs(fn *ssa.Function) [][]*ssa.BasicBlock {
	n := len(fn.Blocks)
	order := make([]int, n)
	lowLink := make([]int, n)
	onStack := make([]bool, n)
	for i := range order {
		order[i] = -1
	}
	var (
		next  int
		stack []*ssa.BasicBlock
		sccs  [][]*ssa.BasicBlock
	)

	var strongConnect func(v *ssa.BasicBlock)
	strongConnect = func(v *ssa.BasicBlock) {
		vi := v.Index
		order[vi], lowLink[vi] = next, next
		next++
		stack = append(stack, v)
		onStack[vi] = true

		for _, w := range v.Succs {
			wi := w.Index
			if order[wi] < 0 {
				strongConnect(w)
				lowLink[vi] = min(lowLink[vi], lowLink[wi])
			} else if onStack[wi] {
				lowLink[vi] = min(lowLink[vi], order[wi])
			}
		}

		if lowLink[vi] == order[vi] {
			var component []*ssa.BasicBlock
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w.Index] = false
				component = append(component, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, component)
		}
	}

	for _, block := range fn.Blocks {
		if order[block.Index] < 0 {
			strongConnect(block)
		}
	}

	return sccs
}

func (c *Canonicalizer) moveInstrToOtherBlock(target ssa.Instruction, dest *ssa.BasicBlock) {
	c.virtualInstrs[target] = dest
}

func (c *Canonicalizer) getVirtualBlock(instr ssa.Instruction) *ssa.BasicBlock {
	if b, ok := c.virtualInstrs[instr]; ok {
		return b
	}
	return instr.Block()
}

func (c *Canonicalizer) getVirtualSuccessors(b *ssa.BasicBlock) []*ssa.BasicBlock {
	if b == nil {
		return nil
	}
	if succs, ok := c.virtualBlocks[b]; ok {
		return succs
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

	// Whitelist of pure mathematical or structural queries
	allowed := name == "len" || name == "cap" || name == "complex" || name == "real" || name == "imag" || name == "min" || name == "max"
	if !allowed {
		return false
	}

	// Note: len() and cap() are impure for Maps and Channels
	// because their length is volatile in concurrent/mutable contexts.
	if name == "len" || name == "cap" {
		if len(call.Call.Args) > 0 {
			arg := call.Call.Args[0]
			t := arg.Type().Underlying()
			switch t.(type) {
			case *types.Map, *types.Chan:
				return false
			}
		}
	}

	return true
}

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
		if _, ok := arg.(*ssa.FreeVar); ok {
			continue
		}
		if instr, ok := arg.(ssa.Instruction); ok {
			if c.hoistedInstrs[instr] {
				// Previously hoisted instructions are effective invariants
				continue
			}
			if instr.Block() != nil && !loopBlocks[instr.Block()] {
				continue
			}
		}
		return false
	}
	return true
}

// initMaps makes the maps a zero Canonicalizer lacks, so one used without
// AcquireCanonicalizer works too.
func (c *Canonicalizer) initMaps() {
	if c.registerMap != nil {
		return
	}
	c.registerMap = make(map[ssa.Value]string)
	c.blockMap = make(map[*ssa.BasicBlock]string)
	c.virtualInstrs = make(map[ssa.Instruction]*ssa.BasicBlock)
	c.virtualBlocks = make(map[*ssa.BasicBlock][]*ssa.BasicBlock)
	c.virtualBinOps = make(map[*ssa.BinOp]token.Token)
	c.hoistedInstrs = make(map[ssa.Instruction]bool)
	c.virtualSubstitutions = make(map[ssa.Value]ssa.Value)
	c.VirtualizedInstrs = make(map[ssa.Instruction]bool)
	c.selectCasePerm = make(map[*ssa.Select][]int)
	c.selectRecvPerm = make(map[*ssa.Select][]int)
	c.typeStrings = make(map[types.Type]string)
}

func (c *Canonicalizer) fullReset() {
	c.initMaps()
	clear(c.virtualBlocks)
	clear(c.virtualBinOps)
	c.resetScratch()
}

// resetScratch clears the per-function state; the virtual control flow
// applied before CanonicalizeFunction survives it.
func (c *Canonicalizer) resetScratch() {
	c.initMaps()
	clear(c.registerMap)
	clear(c.blockMap)
	c.regCounter = 0
	c.output.Reset()
	c.loopInfo = nil
	clear(c.virtualInstrs)
	clear(c.hoistedInstrs)
	clear(c.virtualSubstitutions)
	clear(c.VirtualizedInstrs)
	c.effectiveInstrs = nil
	c.ownPkg = nil
	c.tparams = nil
	clear(c.typeStrings)
	clear(c.selectCasePerm)
	clear(c.selectRecvPerm)
}

func (c *Canonicalizer) normalizeValue(v ssa.Value, preferredName ...string) string {
	if name, exists := c.registerMap[v]; exists {
		return name
	}
	var name string
	if len(preferredName) > 0 {
		name = preferredName[0]
	} else {
		name = "v" + strconv.Itoa(c.regCounter)
		c.regCounter++
	}
	c.registerMap[v] = name
	return name
}

const MaxRenamerDepth = 20

// renamerFunc returns the canonicalizer's SCEV renamer. It names a value
// by its substitution, following chains of substitutions, and guards against
// cycles both in a chain and through recursive SCEV formatting.
func (c *Canonicalizer) renamerFunc() loop.Renamer {
	if c.renamer != nil {
		return c.renamer
	}
	var stack []ssa.Value

	c.renamer = func(v ssa.Value) string {
		if len(stack) >= MaxRenamerDepth {
			return "<depth-limit>"
		}
		for _, s := range stack {
			if s == v {
				return "<cycle>"
			}
		}
		stack = append(stack, v)
		defer func() { stack = stack[:len(stack)-1] }()

		// visited holds the values of the chain after v, so a single
		// substitution allocates nothing.
		current := v
		var visited map[ssa.Value]bool
		for {
			sub, ok := c.virtualSubstitutions[current]
			if !ok {
				break
			}
			if scev, isScev := sub.(loop.SCEV); isScev {
				return loop.FormatSCEV(scev, c.renamer, c.recurrenceLabel)
			}
			if current != v {
				if visited == nil {
					visited = make(map[ssa.Value]bool)
				}
				visited[current] = true
			}
			if sub == v || visited[sub] {
				return "<cycle>"
			}
			current = sub
		}
		return c.normalizeValue(current)
	}
	return c.renamer
}

// recurrenceLabel tags a recurrence with its loop's canonical header block
// and, when known, its integer type: "<b2:int8>". Without it the induction
// variables of nested loops (m[i][j] vs m[j][i]) and of differently sized
// counters render identically.
func (c *Canonicalizer) recurrenceLabel(rec *loop.SCEVAddRec) string {
	header := "?"
	if rec.Loop != nil && rec.Loop.Header != nil {
		if name, ok := c.blockMap[rec.Loop.Header]; ok {
			header = name
		}
	}
	if rec.IntType != nil {
		return "<" + header + ":" + c.sanitizeType(rec.IntType) + ">"
	}
	return "<" + header + ">"
}

// deterministicTraversal returns the blocks reachable from the entry in
// depth-first preorder, visiting each block's (virtual) successors in
// order. go/ssa blocks have at most two successors (If); select and type
// switches are lowered to chains of Ifs.
func (c *Canonicalizer) deterministicTraversal(fn *ssa.Function) []*ssa.BasicBlock {
	if len(fn.Blocks) == 0 {
		return nil
	}
	sortedBlocks := make([]*ssa.BasicBlock, 0, len(fn.Blocks))
	visited := make([]bool, len(fn.Blocks))
	stack := []*ssa.BasicBlock{fn.Blocks[0]}

	for len(stack) > 0 {
		block := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if visited[block.Index] {
			continue
		}
		visited[block.Index] = true
		sortedBlocks = append(sortedBlocks, block)

		succs := c.getVirtualSuccessors(block)
		for i := len(succs) - 1; i >= 0; i-- {
			stack = append(stack, succs[i])
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
		c.output.WriteString(c.registerMap[p])
		c.output.WriteString(": ")
		c.output.WriteString(c.sanitizeType(p.Type()))
	}
	c.output.WriteString(")")
	sig := fn.Signature
	if sig.Results().Len() > 0 {
		c.output.WriteString(" -> (")
		for i := 0; i < sig.Results().Len(); i++ {
			if i > 0 {
				c.output.WriteString(", ")
			}
			c.output.WriteString(c.sanitizeType(sig.Results().At(i).Type()))
		}
		c.output.WriteString(")")
	}
	c.output.WriteString("\n")
}

func (c *Canonicalizer) processBlock(block *ssa.BasicBlock) {
	c.output.WriteString(c.blockMap[block])
	c.output.WriteString(":\n")

	if c.loopInfo != nil {
		if l, ok := c.loopInfo.LoopMap[block]; ok {
			c.output.WriteString("  ; LoopHeader")
			if l.TripCount != nil {
				// The trip count names values through the renamer so they
				// match their names in the rest of the IR.
				c.output.WriteString(" TripCount: ")
				c.output.WriteString(loop.FormatSCEV(l.TripCount, c.renamerFunc(), c.recurrenceLabel))
			}
			c.output.WriteString("\n")
		}
	}

	for _, instr := range c.effectiveInstrs[block.Index] {
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
	c.scratch.Reset()
	val, isValue := instr.(ssa.Value)
	isControlFlow := false

	switch i := instr.(type) {
	case *ssa.Call:
		c.scratch.WriteString("Call ")
		c.writeCallCommon(&c.scratch, &i.Call, instr)
	case *ssa.BinOp:
		normX := c.NormalizeOperand(i.X, instr)
		normY := c.NormalizeOperand(i.Y, instr)
		op := c.getVirtualBinOpToken(i)
		c.scratch.WriteString("BinOp ")
		c.scratch.WriteString(op.String())
		c.scratch.WriteString(", ")
		if isCommutative(i) && normX > normY {
			c.scratch.WriteString(normY)
			c.scratch.WriteString(", ")
			c.scratch.WriteString(normX)
		} else {
			c.scratch.WriteString(normX)
			c.scratch.WriteString(", ")
			c.scratch.WriteString(normY)
		}
	case *ssa.UnOp:
		c.scratch.WriteString("UnOp ")
		c.scratch.WriteString(i.Op.String())
		c.scratch.WriteString(", ")
		c.scratch.WriteString(c.NormalizeOperand(i.X, instr))
		if i.CommaOk {
			c.scratch.WriteString(", CommaOk")
		}
	case *ssa.Phi:
		c.writePhi(&c.scratch, i, instr)
	case *ssa.Alloc:
		c.scratch.WriteString("Alloca ")
		handled := false
		if ptrType, ok := i.Type().Underlying().(*types.Pointer); ok {
			elemType := ptrType.Elem()
			if arrType, ok := elemType.Underlying().(*types.Array); ok {
				length := arrType.Len()
				typeRep := c.sanitizeType(elemType)
				if length >= 0 {
					lenConst := ssa.NewConst(constant.MakeInt64(length), types.Typ[types.Int])
					if c.Policy.ShouldAbstract(lenConst, instr) {
						typeRep = fmt.Sprintf("[<len_literal>]%s", c.sanitizeType(arrType.Elem()))
					}
				}
				c.scratch.WriteString(typeRep)
				handled = true
			} else {
				c.scratch.WriteString(c.sanitizeType(elemType))
				handled = true
			}
		}
		if !handled {
			c.scratch.WriteString(c.sanitizeType(i.Type().Underlying()))
		}
	case *ssa.Store:
		c.scratch.WriteString("Store ")
		c.scratch.WriteString(c.NormalizeOperand(i.Addr, instr))
		c.scratch.WriteString(", ")
		c.scratch.WriteString(c.NormalizeOperand(i.Val, instr))
	case *ssa.If:
		isControlFlow = true
		succs := c.getVirtualSuccessors(i.Block())
		c.scratch.WriteString("If ")
		c.scratch.WriteString(c.NormalizeOperand(i.Cond, instr))
		c.scratch.WriteString(", ")
		c.scratch.WriteString(c.blockMap[succs[0]])
		c.scratch.WriteString(", ")
		c.scratch.WriteString(c.blockMap[succs[1]])
	case *ssa.Jump:
		isControlFlow = true
		if len(i.Block().Succs) > 0 {
			c.scratch.WriteString("Jump ")
			c.scratch.WriteString(c.blockMap[i.Block().Succs[0]])
		} else {
			c.scratch.WriteString("Jump <invalid>")
		}
	case *ssa.Return:
		isControlFlow = true
		c.scratch.WriteString("Return")
		for j, res := range i.Results {
			if j > 0 {
				c.scratch.WriteString(",")
			}
			c.scratch.WriteString(" ")
			c.scratch.WriteString(c.NormalizeOperand(res, instr))
		}
	case *ssa.IndexAddr:
		fmt.Fprintf(&c.scratch, "IndexAddr %s, %s", c.NormalizeOperand(i.X, instr), c.NormalizeOperand(i.Index, instr))
	case *ssa.Index:
		fmt.Fprintf(&c.scratch, "Index %s, %s", c.NormalizeOperand(i.X, instr), c.NormalizeOperand(i.Index, instr))
	case *ssa.Select:
		c.writeSelect(&c.scratch, i, instr)
	case *ssa.Range:
		fmt.Fprintf(&c.scratch, "Range %s", c.NormalizeOperand(i.X, instr))
	case *ssa.Next:
		fmt.Fprintf(&c.scratch, "Next %s", c.NormalizeOperand(i.Iter, instr))
	case *ssa.Extract:
		fmt.Fprintf(&c.scratch, "Extract %s, %d", c.NormalizeOperand(i.Tuple, instr), c.remappedExtractIndex(i))
	case *ssa.Slice:
		fmt.Fprintf(&c.scratch, "Slice %s", c.NormalizeOperand(i.X, instr))
		if i.Low != nil {
			fmt.Fprintf(&c.scratch, ", Low:%s", c.NormalizeOperand(i.Low, instr))
		}
		if i.High != nil {
			fmt.Fprintf(&c.scratch, ", High:%s", c.NormalizeOperand(i.High, instr))
		}
		if i.Max != nil {
			fmt.Fprintf(&c.scratch, ", Max:%s", c.NormalizeOperand(i.Max, instr))
		}
	case *ssa.MakeSlice:
		fmt.Fprintf(&c.scratch, "MakeSlice %s, Len:%s, Cap:%s", c.sanitizeType(i.Type()), c.NormalizeOperand(i.Len, instr), c.NormalizeOperand(i.Cap, instr))
	case *ssa.MakeMap:
		fmt.Fprintf(&c.scratch, "MakeMap %s", c.sanitizeType(i.Type()))
		if i.Reserve != nil {
			fmt.Fprintf(&c.scratch, ", Reserve:%s", c.NormalizeOperand(i.Reserve, instr))
		}
	case *ssa.MapUpdate:
		fmt.Fprintf(&c.scratch, "MapUpdate %s, Key:%s, Val:%s", c.NormalizeOperand(i.Map, instr), c.NormalizeOperand(i.Key, instr), c.NormalizeOperand(i.Value, instr))
	case *ssa.Lookup:
		fmt.Fprintf(&c.scratch, "Lookup %s, Key:%s", c.NormalizeOperand(i.X, instr), c.NormalizeOperand(i.Index, instr))
		if i.CommaOk {
			c.scratch.WriteString(", CommaOk")
		}
	case *ssa.TypeAssert:
		fmt.Fprintf(&c.scratch, "TypeAssert %s, AssertedType:%s", c.NormalizeOperand(i.X, instr), c.sanitizeType(i.AssertedType))
		if i.CommaOk {
			c.scratch.WriteString(", CommaOk")
		}
	case *ssa.MakeInterface:
		fmt.Fprintf(&c.scratch, "MakeInterface %s, %s", c.sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr))
	case *ssa.ChangeType:
		fmt.Fprintf(&c.scratch, "ChangeType %s, %s", c.sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr))
	case *ssa.Convert:
		fmt.Fprintf(&c.scratch, "Convert %s, %s", c.sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr))
	case *ssa.Go:
		c.scratch.WriteString("Go ")
		c.writeCallCommon(&c.scratch, &i.Call, instr)
	case *ssa.Defer:
		c.scratch.WriteString("Defer ")
		c.writeCallCommon(&c.scratch, &i.Call, instr)
	case *ssa.RunDefers:
		c.scratch.WriteString("RunDefers")
	case *ssa.Panic:
		fmt.Fprintf(&c.scratch, "Panic %s", c.NormalizeOperand(i.X, instr))
	case *ssa.MakeClosure:
		fmt.Fprintf(&c.scratch, "MakeClosure %s", c.NormalizeOperand(i.Fn, instr))
		if len(i.Bindings) > 0 {
			c.scratch.WriteString(" [")
			for j, binding := range i.Bindings {
				if j > 0 {
					c.scratch.WriteString(", ")
				}
				c.scratch.WriteString(c.NormalizeOperand(binding, instr))
			}
			c.scratch.WriteString("]")
		}
	case *ssa.FieldAddr:
		fmt.Fprintf(&c.scratch, "FieldAddr %s, field(%s)", c.NormalizeOperand(i.X, instr), FieldName(i.X, i.Field))
	case *ssa.Field:
		fmt.Fprintf(&c.scratch, "Field %s, field(%s)", c.NormalizeOperand(i.X, instr), FieldName(i.X, i.Field))
	case *ssa.Send:
		fmt.Fprintf(&c.scratch, "Send %s, %s", c.NormalizeOperand(i.Chan, instr), c.NormalizeOperand(i.X, instr))
	case *ssa.MakeChan:
		fmt.Fprintf(&c.scratch, "MakeChan %s, Size:%s", c.sanitizeType(i.Type()), c.NormalizeOperand(i.Size, instr))
	case *ssa.ChangeInterface:
		fmt.Fprintf(&c.scratch, "ChangeInterface %s, %s", c.sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr))
	case *ssa.SliceToArrayPointer:
		fmt.Fprintf(&c.scratch, "SliceToArrayPointer %s, %s", c.sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr))
	case *ssa.MultiConvert:
		fmt.Fprintf(&c.scratch, "MultiConvert %s, %s", c.sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr))
	case *ssa.DebugRef:
		return

	default:
		if c.StrictMode {
			panic(fmt.Sprintf("STRICT MODE: Unhandled SSA instruction %T", instr))
		}
		fmt.Fprintf(&c.scratch, "UnhandledInstr<%T>", instr)
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
			c.output.WriteString(c.normalizeValue(val))
			c.output.WriteString(" = ")
		}
	}
	c.output.Write(c.scratch.Bytes())
	c.output.WriteByte('\n')
}

func (c *Canonicalizer) writeSelect(w *bytes.Buffer, i *ssa.Select, context ssa.Instruction) {
	w.WriteString("Select")
	if i.Blocking {
		w.WriteString(" [blocking]")
	} else {
		w.WriteString(" [non-blocking]")
	}

	// selectStateCanon captures the canonicalized representation of each case.
	// Use origIndex to track the original position for Extract instruction correlation,
	// but sort by canonical form to produce stable fingerprints across case reordering.
	type selectStateCanon struct {
		origIndex   int    // Original index in States slice, for renumbering Extracts
		dir         string // Direction: "->" (send), "<-" (recv), or "?" (unknown)
		chanRepr    string // Canonical representation of channel operand
		sendValRepr string // Canonical representation of sent value (for sends only)
		sortKey     string // Pre-computed key for deterministic sorting
	}

	var states []selectStateCanon

	// Non-blocking selects have an implicit default case. We represent it canonically.
	if !i.Blocking {
		states = append(states, selectStateCanon{
			origIndex: -1,
			dir:       "<-",
			chanRepr:  "<default>",
			sortKey:   "\x00<default>", // Sort default first with null prefix
		})
	}

	for idx, state := range i.States {
		dirStr := "?"
		switch state.Dir {
		case types.SendOnly:
			dirStr = "->"
		case types.RecvOnly:
			dirStr = "<-"
		}

		s := selectStateCanon{origIndex: idx, dir: dirStr}
		if state.Chan != nil {
			s.chanRepr = c.NormalizeOperand(state.Chan, context)
		} else {
			s.chanRepr = "<nil_chan>"
		}

		if state.Send != nil {
			s.sendValRepr = c.NormalizeOperand(state.Send, context)
		}

		// Build sort key: direction + channel + optional send value
		// This ensures semantically equivalent cases have identical keys.
		s.sortKey = s.dir + s.chanRepr
		if s.sendValRepr != "" {
			s.sortKey += "<-" + s.sendValRepr
		}

		states = append(states, s)
	}

	// Sort select cases to produce deterministic fingerprints.
	// The Go spec does not define case evaluation order for select when multiple
	// channels are ready (it's random at runtime). Therefore, reordering cases
	// in source code is a semantically neutral refactor that should not change
	// the fingerprint.
	sort.SliceStable(states, func(a, b int) bool {
		return states[a].sortKey < states[b].sortKey
	})

	// Sorting alone would detach each case from its body: the case index the
	// Select yields (and the position of each received value in its tuple)
	// still refer to source order, so swapping two cases' bodies would leave
	// the rendering unchanged. Record where each case landed so the index
	// comparisons and Extracts that consume it are renumbered to match.
	casePerm := make([]int, len(i.States))
	recvOrdinal := make([]int, len(i.States)) // state index -> source-order receive ordinal
	n := 0
	for idx, st := range i.States {
		if st.Dir == types.RecvOnly {
			recvOrdinal[idx] = n
			n++
		}
	}
	recvPerm := make([]int, n)
	pos, recvPos := 0, 0
	for _, st := range states {
		if st.origIndex < 0 {
			continue
		}
		casePerm[st.origIndex] = pos
		pos++
		if i.States[st.origIndex].Dir == types.RecvOnly {
			recvPerm[recvOrdinal[st.origIndex]] = recvPos
			recvPos++
		}
	}
	c.selectCasePerm[i] = casePerm
	c.selectRecvPerm[i] = recvPerm

	for _, state := range states {
		fmt.Fprintf(w, " (%s %s", state.dir, state.chanRepr)
		if state.sendValRepr != "" {
			fmt.Fprintf(w, " <- %s", state.sendValRepr)
		}
		w.WriteString(")")
	}
}

// selectIndexOf reports the Select whose chosen-case index v is, if v is
// Extract #0 of a Select tuple.
func selectIndexOf(v ssa.Value) *ssa.Select {
	if ext, ok := v.(*ssa.Extract); ok && ext.Index == 0 {
		if sel, ok := ext.Tuple.(*ssa.Select); ok {
			return sel
		}
	}
	return nil
}

// remappedSelectCase renumbers a case-index constant compared against a
// Select's chosen index to the case's position in the sorted rendering.
func (c *Canonicalizer) remappedSelectCase(k *ssa.Const, context ssa.Instruction) (int64, bool) {
	bin, ok := context.(*ssa.BinOp)
	if !ok || k.Value == nil || k.Value.Kind() != constant.Int {
		return 0, false
	}
	sel := selectIndexOf(bin.X)
	if sel == nil {
		sel = selectIndexOf(bin.Y)
	}
	if sel == nil {
		return 0, false
	}
	perm, ok := c.selectCasePerm[sel]
	if !ok {
		return 0, false
	}
	idx, exact := constant.Int64Val(k.Value)
	if !exact || idx < 0 || idx >= int64(len(perm)) {
		return 0, false // e.g. -1, the non-blocking default
	}
	return int64(perm[idx]), true
}

// remappedExtractIndex renumbers the received-value slots of a Select tuple
// (index 2+j holds the j-th receive case's value) to sorted receive order.
func (c *Canonicalizer) remappedExtractIndex(ext *ssa.Extract) int {
	sel, ok := ext.Tuple.(*ssa.Select)
	if !ok || ext.Index < 2 {
		return ext.Index
	}
	perm, ok := c.selectRecvPerm[sel]
	if !ok || ext.Index-2 >= len(perm) {
		return ext.Index
	}
	return 2 + perm[ext.Index-2]
}

// writePhi renders a phi's edges ordered by their predecessors' canonical
// block numbers, so the rendering does not depend on go/ssa's predecessor
// order.
func (c *Canonicalizer) writePhi(w *bytes.Buffer, i *ssa.Phi, instr ssa.Instruction) {
	w.WriteString("Phi")
	type edge struct {
		pred  string // the predecessor's canonical name, "b<n>"
		n     int
		value string
	}
	preds := i.Block().Preds
	edges := make([]edge, 0, len(i.Edges))
	for j, val := range i.Edges {
		if j >= len(preds) {
			break
		}
		pred := c.blockMap[preds[j]]
		n, _ := strconv.Atoi(strings.TrimPrefix(pred, "b"))
		edges = append(edges, edge{pred: pred, n: n, value: c.NormalizeOperand(val, instr)})
	}
	sort.SliceStable(edges, func(a, b int) bool { return edges[a].n < edges[b].n })
	for _, e := range edges {
		fmt.Fprintf(w, " [%s: %s]", e.pred, e.value)
	}
}

func (c *Canonicalizer) writeCallCommon(w *bytes.Buffer, common *ssa.CallCommon, context ssa.Instruction) {
	if common.IsInvoke() {
		w.WriteString("Invoke ")
		w.WriteString(c.NormalizeOperand(common.Value, context))
		w.WriteString(".")
		w.WriteString(common.Method.Name())
	} else {
		w.WriteString(c.NormalizeOperand(common.Value, context))
	}
	w.WriteString("(")
	for i, arg := range common.Args {
		if i > 0 {
			w.WriteString(", ")
		}
		w.WriteString(c.NormalizeOperand(arg, context))
	}
	w.WriteString(")")
}

func (c *Canonicalizer) NormalizeOperand(v ssa.Value, context ssa.Instruction) string {
	if v == nil {
		return "<nil>"
	}
	c.initMaps()
	// Follow v's substitutions, short of the instruction being rendered,
	// stopping at the first value seen twice. visited holds the values seen
	// after start, so a single substitution allocates nothing.
	start := v
	var visited map[ssa.Value]bool
	for {
		sub, ok := c.virtualSubstitutions[v]
		if !ok {
			break
		}
		if subInstr, isInstr := sub.(ssa.Instruction); isInstr && subInstr == context {
			break
		}
		if v != start {
			if visited == nil {
				visited = make(map[ssa.Value]bool)
			}
			visited[v] = true
		}
		v = sub
		if v == start || visited[v] {
			break
		}
	}

	switch operand := v.(type) {
	case loop.SCEV:
		return loop.FormatSCEV(operand, c.renamerFunc(), c.recurrenceLabel)
	case *ssa.Const:
		if k, ok := c.remappedSelectCase(operand, context); ok {
			return fmt.Sprintf("const(%d)", k)
		}
		if c.Policy.ShouldAbstract(operand, context) {
			return fmt.Sprintf("<%s_literal>", c.sanitizeType(operand.Type()))
		}
		if operand.Value == nil {
			return fmt.Sprintf("const(%s:nil)", c.sanitizeType(operand.Type()))
		}
		if operand.Value.Kind() == constant.String {
			return fmt.Sprintf("const(%q)", constant.StringVal(operand.Value))
		}
		return fmt.Sprintf("const(%s)", operand.Value.ExactString())
	case *ssa.Global:
		pkgPath := ""
		if operand.Pkg != nil {
			pkgPath = c.qualifier(operand.Pkg.Pkg)
		}
		return fmt.Sprintf("<global:%s.%s:%s>", pkgPath, operand.Name(), c.sanitizeType(operand.Type()))
	case *ssa.Builtin:
		return "<builtin:" + operand.Name() + ">"
	case *ssa.Function:
		if name, exists := c.registerMap[v]; exists {
			return name
		}
		// RelString keeps the receiver and, outside the own package, the
		// import path: "(*os/exec.Cmd).Run", "crypto/rand.Read". Name()
		// alone made same-named, same-signature functions from different
		// packages (crypto/rand.Read vs math/rand.Read) or receivers
		// indistinguishable.
		sig := c.sanitizeType(operand.Signature)
		if isInstance(operand) {
			sig = sanitizeTypeWith(c.tparams.instanceType(operand, operand.Signature), c.qualifier)
		}
		return fmt.Sprintf("<func_ref:%s:%s>", c.tparams.FuncName(operand, c.ownPkg), sig)
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

// FieldName names field index of x's struct type, where x is a struct or a
// pointer to one, as Field and FieldAddr select it. A field is identified by
// its name, not its position: reordering a struct's fields must not change a
// function that reads them, and reading a different field that moved into
// the old one's position must. Falls back to "#index" when x's type is not a
// struct.
func FieldName(x ssa.Value, index int) string {
	t := x.Type().Underlying()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem().Underlying()
	}
	if s, ok := t.(*types.Struct); ok && index >= 0 && index < s.NumFields() {
		return s.Field(index).Name()
	}
	return "#" + strconv.Itoa(index)
}

func (c *Canonicalizer) sanitizeType(t types.Type) string {
	if s, ok := c.typeStrings[t]; ok {
		return s
	}
	s := sanitizeTypeWith(c.tparams.Rename(t), c.qualifier)
	c.typeStrings[t] = s
	return s
}

func sanitizeTypeWith(t types.Type, q types.Qualifier) string {
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
					elemStr := types.TypeString(slice.Elem(), q)
					params = append(params, "..."+elemStr)
					continue
				}
			}
			params = append(params, sanitizeTypeWith(paramType, q))
		}

		var results []string
		for i := 0; i < sig.Results().Len(); i++ {
			results = append(results, sanitizeTypeWith(sig.Results().At(i).Type(), q))
		}

		resStr := ""
		if len(results) > 0 {
			resStr = " (" + strings.Join(results, ", ") + ")"
		}

		res = fmt.Sprintf("func(%s)%s", strings.Join(params, ", "), resStr)
	} else {
		res = types.TypeString(t, q)
	}

	return strings.ReplaceAll(res, "\n", " ")
}
