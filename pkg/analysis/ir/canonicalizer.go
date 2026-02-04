package ir

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/loop"
	"golang.org/x/tools/go/ssa"
)

// MaxLoopAnalysisDepth prevents stack overflow attacks from deeply nested loops during IV normalization.
const MaxLoopAnalysisDepth = 64

type virtualInstr struct {
	instr        ssa.Instruction
	virtualBlock *ssa.BasicBlock
}

type virtualBlock struct {
	block        *ssa.BasicBlock
	virtualSuccs [2]*ssa.BasicBlock
	swapped      bool
}

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
			VirtualizedInstrs:    make(map[ssa.Instruction]bool),
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

type Canonicalizer struct {
	Policy     LiteralPolicy
	StrictMode bool

	loopInfo *loop.LoopInfo

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
	VirtualizedInstrs    map[ssa.Instruction]bool
}

func NewCanonicalizer(policy LiteralPolicy) *Canonicalizer {
	return AcquireCanonicalizer(policy)
}

func (c *Canonicalizer) ApplyVirtualControlFlowFromState(swappedBlocks map[*ssa.BasicBlock]bool, virtualBinOps map[*ssa.BinOp]token.Token) {
	// Sort blocks to ensure deterministic population of virtualBlocks
	var blocks []*ssa.BasicBlock
	for block := range swappedBlocks {
		blocks = append(blocks, block)
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].Index < blocks[j].Index })

	for _, block := range blocks {
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
	estimatedSize := 0
	for _, block := range fn.Blocks {
		estimatedSize += len(block.Instrs) * 50
	}
	c.output.Grow(estimatedSize)

	// Normalize parameters first to ensure they receive reserved names (p0, p1...)
	// before any analysis passes (like SCEV) potentially reference them.
	for i, param := range fn.Params {
		c.normalizeValue(param, fmt.Sprintf("p%d", i))
	}
	for i, fv := range fn.FreeVars {
		c.normalizeValue(fv, fmt.Sprintf("fv%d", i))
	}

	c.AnalyzeLoops(fn)
	c.hoistInvariantCalls(fn)
	c.NormalizeInductionVariables()

	sortedBlocks := c.deterministicTraversal(fn)
	visited := make(map[*ssa.BasicBlock]bool)
	for _, b := range sortedBlocks {
		visited[b] = true
	}
	var unreachables []*ssa.BasicBlock
	for _, b := range fn.Blocks {
		if !visited[b] {
			unreachables = append(unreachables, b)
		}
	}
	sort.Slice(unreachables, func(i, j int) bool { return unreachables[i].Index < unreachables[j].Index })
	sortedBlocks = append(sortedBlocks, unreachables...)

	for i, block := range sortedBlocks {
		c.blockMap[block] = fmt.Sprintf("b%d", i)
	}

	c.writeFunctionSignature(fn)
	c.reconstructBlockInstructions(fn)
	for _, block := range sortedBlocks {
		if _, exists := c.blockMap[block]; exists {
			c.processBlock(block)
		}
	}

	return c.output.String()
}

func (c *Canonicalizer) AnalyzeLoops(fn *ssa.Function) {
	if len(fn.Blocks) == 0 {
		return
	}
	c.loopInfo = loop.DetectLoops(fn)
	loop.AnalyzeSCEV(c.loopInfo)
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
				scev := &loop.SCEVAddRec{Start: iv.Start, Step: iv.Step, Loop: l}
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
					c.VirtualizedInstrs[binOp] = true
					c.virtualSubstitutions[binOp] = addRec
				}
			}
		}
	}
}

func (c *Canonicalizer) reconstructBlockInstructions(fn *ssa.Function) {
	c.effectiveInstrs = make(map[*ssa.BasicBlock][]ssa.Instruction)

	// Separate instruction lists to enforce safe ordering:
	// 1. Phis (must be first)
	// 2. Heads (Sunk instructions - execute before body)
	// 3. Bodies (Native instructions)
	// 4. Tails (Hoisted instructions - execute at end)
	// 5. Terminators
	phis := make(map[*ssa.BasicBlock][]ssa.Instruction)
	heads := make(map[*ssa.BasicBlock][]ssa.Instruction)
	bodies := make(map[*ssa.BasicBlock][]ssa.Instruction)
	tails := make(map[*ssa.BasicBlock][]ssa.Instruction)
	terminators := make(map[*ssa.BasicBlock]ssa.Instruction)

	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if c.VirtualizedInstrs[instr] {
				continue
			}

			targetBlock := c.getVirtualBlock(instr)
			isTerm := isTerminator(instr)

			if isTerm && targetBlock == b {
				terminators[b] = instr
				continue
			}

			// Keep Phis at the start of their native block
			if _, ok := instr.(*ssa.Phi); ok && targetBlock == b {
				phis[b] = append(phis[b], instr)
				continue
			}

			// Classify instruction placement
			if c.sunkInstrs[instr] {
				// Sunk instructions (moved down) typically must execute before the native body
				heads[targetBlock] = append(heads[targetBlock], instr)
			} else if c.hoistedInstrs[instr] || targetBlock != b {
				// Hoisted instructions (moved up) or generic moves usually go to tail (e.g. preheader)
				tails[targetBlock] = append(tails[targetBlock], instr)
			} else {
				// Native instructions stay in body
				bodies[targetBlock] = append(bodies[targetBlock], instr)
			}
		}
	}

	for _, b := range fn.Blocks {
		var combined []ssa.Instruction
		combined = append(combined, phis[b]...)
		combined = append(combined, heads[b]...)
		combined = append(combined, bodies[b]...)
		// Appending in discovery order (which is usually topological for hoists) preserves dependencies.
		combined = append(combined, tails[b]...)

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

	if c.VirtualizedInstrs != nil {
		for k := range c.VirtualizedInstrs {
			delete(c.VirtualizedInstrs, k)
		}
	} else {
		c.VirtualizedInstrs = make(map[ssa.Instruction]bool)
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

const MaxRenamerDepth = 20

func (c *Canonicalizer) renamerFunc() loop.Renamer {
	// Optimization: Slice-based stack avoids map allocation overhead
	var stack []ssa.Value
	depth := 0

	var renamer loop.Renamer
	renamer = func(v ssa.Value) string {
		if depth >= MaxRenamerDepth {
			return "<depth-limit>"
		}

		// Check for cycle in current recursion stack
		for _, s := range stack {
			if s == v {
				return "<cycle>"
			}
		}

		stack = append(stack, v)
		depth++
		defer func() {
			depth--
			stack = stack[:len(stack)-1]
		}()

		visited := make(map[ssa.Value]bool)
		current := v

		for {
			// BUG FIX: Detect cycle in iterative substitution
			if visited[current] {
				return "<cycle>"
			}
			visited[current] = true

			sub, ok := c.virtualSubstitutions[current]
			if !ok {
				break
			}

			if scev, isScev := sub.(loop.SCEV); isScev {
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
			// Binary branches (if-then-else): preserve true/false order.
			stack = append(stack, succs[1])
			stack = append(stack, succs[0])
		} else if len(succs) > 2 {
			// Multi-way branches (select, typeswitch) can have successors
			// in an order that depends on AST position or compiler version. Sort them
			// canonically by their structural fingerprint to ensure deterministic traversal.
			//
			// Sort by: block's first instruction type, then instruction count, then original index.
			// This produces a stable order based on block content rather than emission order.
			orderedSuccs := make([]*ssa.BasicBlock, len(succs))
			copy(orderedSuccs, succs)
			sort.SliceStable(orderedSuccs, func(i, j int) bool {
				return c.blockSortKey(orderedSuccs[i]) < c.blockSortKey(orderedSuccs[j])
			})
			// Push in reverse order so first in sorted order is processed first
			for i := len(orderedSuccs) - 1; i >= 0; i-- {
				stack = append(stack, orderedSuccs[i])
			}
		} else {
			// 0 or 1 successor: no ambiguity
			for i := len(succs) - 1; i >= 0; i-- {
				stack = append(stack, succs[i])
			}
		}
	}
	return sortedBlocks
}

// Generates a canonical key for sorting basic blocks.
// The key is designed to be stable across AST reorderings and compiler versions
// by focusing on structural properties rather than positional indices.
func (c *Canonicalizer) blockSortKey(b *ssa.BasicBlock) string {
	if b == nil || len(b.Instrs) == 0 {
		return "\xff" // Sort empty blocks last
	}

	// Build key from: first instruction type, instruction count, original index as tiebreaker
	firstInstr := b.Instrs[0]
	instrType := fmt.Sprintf("%T", firstInstr)

	// Include a structural fingerprint of the first few instructions
	var keyParts []string
	keyParts = append(keyParts, instrType)
	keyParts = append(keyParts, fmt.Sprintf("%03d", len(b.Instrs)))

	// Sample up to 3 instruction types for better discrimination
	for i := 0; i < 3 && i < len(b.Instrs); i++ {
		keyParts = append(keyParts, fmt.Sprintf("%T", b.Instrs[i]))
	}

	// Original index as final tiebreaker for complete determinism
	keyParts = append(keyParts, fmt.Sprintf("%05d", b.Index))

	return strings.Join(keyParts, "|")
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

	if c.loopInfo != nil {
		if loop, ok := c.loopInfo.LoopMap[block]; ok {
			c.output.WriteString("  ; LoopHeader")
			if loop.TripCount != nil {
				// BUG FIX: Use renamer to ensure TripCount variables match the rest of the IR
				c.output.WriteString(fmt.Sprintf(" TripCount: %s", loop.TripCount.StringWithRenamer(c.renamerFunc())))
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
		normX := c.NormalizeOperand(i.X, instr)
		normY := c.NormalizeOperand(i.Y, instr)
		op := c.getVirtualBinOpToken(i)
		if isCommutative(i) && normX > normY {
			rhs.WriteString(fmt.Sprintf("BinOp %s, %s, %s", op.String(), normY, normX))
		} else {
			rhs.WriteString(fmt.Sprintf("BinOp %s, %s, %s", op.String(), normX, normY))
		}
	case *ssa.UnOp:
		rhs.WriteString(fmt.Sprintf("UnOp %s, %s", i.Op.String(), c.NormalizeOperand(i.X, instr)))
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
		rhs.WriteString(fmt.Sprintf("Store %s, %s", c.NormalizeOperand(i.Addr, instr), c.NormalizeOperand(i.Val, instr)))
	case *ssa.If:
		isControlFlow = true
		succs := c.getVirtualSuccessors(i.Block())
		rhs.WriteString(fmt.Sprintf("If %s, %s, %s", c.NormalizeOperand(i.Cond, instr), c.blockMap[succs[0]], c.blockMap[succs[1]]))
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
			rhs.WriteString(" " + c.NormalizeOperand(res, instr))
		}
	case *ssa.IndexAddr:
		rhs.WriteString(fmt.Sprintf("IndexAddr %s, %s", c.NormalizeOperand(i.X, instr), c.NormalizeOperand(i.Index, instr)))
	case *ssa.Index:
		rhs.WriteString(fmt.Sprintf("Index %s, %s", c.NormalizeOperand(i.X, instr), c.NormalizeOperand(i.Index, instr)))
	case *ssa.Select:
		c.writeSelect(&rhs, i, instr)
	case *ssa.Range:
		rhs.WriteString(fmt.Sprintf("Range %s", c.NormalizeOperand(i.X, instr)))
	case *ssa.Next:
		rhs.WriteString(fmt.Sprintf("Next %s", c.NormalizeOperand(i.Iter, instr)))
	case *ssa.Extract:
		rhs.WriteString(fmt.Sprintf("Extract %s, %d", c.NormalizeOperand(i.Tuple, instr), i.Index))
	case *ssa.Slice:
		rhs.WriteString(fmt.Sprintf("Slice %s", c.NormalizeOperand(i.X, instr)))
		if i.Low != nil {
			rhs.WriteString(fmt.Sprintf(", Low:%s", c.NormalizeOperand(i.Low, instr)))
		}
		if i.High != nil {
			rhs.WriteString(fmt.Sprintf(", High:%s", c.NormalizeOperand(i.High, instr)))
		}
		if i.Max != nil {
			rhs.WriteString(fmt.Sprintf(", Max:%s", c.NormalizeOperand(i.Max, instr)))
		}
	case *ssa.MakeSlice:
		rhs.WriteString(fmt.Sprintf("MakeSlice %s, Len:%s, Cap:%s", sanitizeType(i.Type()), c.NormalizeOperand(i.Len, instr), c.NormalizeOperand(i.Cap, instr)))
	case *ssa.MakeMap:
		rhs.WriteString(fmt.Sprintf("MakeMap %s", sanitizeType(i.Type())))
		if i.Reserve != nil {
			rhs.WriteString(fmt.Sprintf(", Reserve:%s", c.NormalizeOperand(i.Reserve, instr)))
		}
	case *ssa.MapUpdate:
		rhs.WriteString(fmt.Sprintf("MapUpdate %s, Key:%s, Val:%s", c.NormalizeOperand(i.Map, instr), c.NormalizeOperand(i.Key, instr), c.NormalizeOperand(i.Value, instr)))
	case *ssa.Lookup:
		rhs.WriteString(fmt.Sprintf("Lookup %s, Key:%s", c.NormalizeOperand(i.X, instr), c.NormalizeOperand(i.Index, instr)))
		if i.CommaOk {
			rhs.WriteString(", CommaOk")
		}
	case *ssa.TypeAssert:
		rhs.WriteString(fmt.Sprintf("TypeAssert %s, AssertedType:%s", c.NormalizeOperand(i.X, instr), sanitizeType(i.AssertedType)))
		if i.CommaOk {
			rhs.WriteString(", CommaOk")
		}
	case *ssa.MakeInterface:
		rhs.WriteString(fmt.Sprintf("MakeInterface %s, %s", sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr)))
	case *ssa.ChangeType:
		rhs.WriteString(fmt.Sprintf("ChangeType %s, %s", sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr)))
	case *ssa.Convert:
		rhs.WriteString(fmt.Sprintf("Convert %s, %s", sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr)))
	case *ssa.Go:
		rhs.WriteString("Go ")
		c.writeCallCommon(&rhs, &i.Call, instr)
	case *ssa.Defer:
		rhs.WriteString("Defer ")
		c.writeCallCommon(&rhs, &i.Call, instr)
	case *ssa.RunDefers:
		rhs.WriteString("RunDefers")
	case *ssa.Panic:
		rhs.WriteString(fmt.Sprintf("Panic %s", c.NormalizeOperand(i.X, instr)))
	case *ssa.MakeClosure:
		rhs.WriteString(fmt.Sprintf("MakeClosure %s", c.NormalizeOperand(i.Fn, instr)))
		if len(i.Bindings) > 0 {
			rhs.WriteString(" [")
			for j, binding := range i.Bindings {
				if j > 0 {
					rhs.WriteString(", ")
				}
				rhs.WriteString(c.NormalizeOperand(binding, instr))
			}
			rhs.WriteString("]")
		}
	case *ssa.FieldAddr:
		rhs.WriteString(fmt.Sprintf("FieldAddr %s, field(%d)", c.NormalizeOperand(i.X, instr), i.Field))
	case *ssa.Field:
		rhs.WriteString(fmt.Sprintf("Field %s, field(%d)", c.NormalizeOperand(i.X, instr), i.Field))
	case *ssa.Send:
		rhs.WriteString(fmt.Sprintf("Send %s, %s", c.NormalizeOperand(i.Chan, instr), c.NormalizeOperand(i.X, instr)))
	case *ssa.MakeChan:
		rhs.WriteString(fmt.Sprintf("MakeChan %s, Size:%s", sanitizeType(i.Type()), c.NormalizeOperand(i.Size, instr)))
	case *ssa.ChangeInterface:
		rhs.WriteString(fmt.Sprintf("ChangeInterface %s, %s", sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr)))
	case *ssa.SliceToArrayPointer:
		rhs.WriteString(fmt.Sprintf("SliceToArrayPointer %s, %s", sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr)))
	case *ssa.MultiConvert:
		rhs.WriteString(fmt.Sprintf("MultiConvert %s, %s", sanitizeType(i.Type()), c.NormalizeOperand(i.X, instr)))
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

	// selectStateCanon captures the canonicalized representation of each case.
	// Use origIndex to track the original position for Extract instruction correlation,
	// but sort by canonical form to produce stable fingerprints across case reordering.
	type selectStateCanon struct {
		origIndex   int    // Original index in States slice (for documentation/debugging)
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
	//
	// Note: The Select instruction's return value includes an index indicating
	// which case was chosen. Code that depends on this index (via Extract) will
	// still work correctly because we're only canonicalizing the *representation*
	// for fingerprinting, not modifying the actual SSA. The Extract indices
	// remain bound to original positions.
	sort.SliceStable(states, func(a, b int) bool {
		return states[a].sortKey < states[b].sortKey
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
		if j >= len(preds) {
			break
		}
		predBlock := preds[j]
		predID := c.blockMap[predBlock]

		// BUG FIX: Robust predecessor index parsing and fallback
		if predID == "" || len(predID) < 2 {
			predID = fmt.Sprintf("b%d", predBlock.Index)
		}
		idx := -1
		if len(predID) > 1 && predID[0] == 'b' {
			if val, err := strconv.Atoi(predID[1:]); err == nil {
				idx = val
			}
		}

		valStr := c.NormalizeOperand(val, instr)
		if overrides, ok := c.virtualPhiConstants[i]; ok {
			if ov, ok := overrides[j]; ok {
				valStr = ov
			}
		}

		edges = append(edges, edge{predID: predID, predIndex: idx, value: valStr})
	}

	// Deterministic sorting logic for Phi edges
	sort.SliceStable(edges, func(a, b int) bool {
		// Primary: Numeric index if available
		if edges[a].predIndex != -1 && edges[b].predIndex != -1 {
			return edges[a].predIndex < edges[b].predIndex
		}
		// Secondary: Lexicographical sort on ID (fallback)
		return edges[a].predID < edges[b].predID
	})

	for _, e := range edges {
		w.WriteString(fmt.Sprintf(" [%s: %s]", e.predID, e.value))
	}
}

func (c *Canonicalizer) writeCallCommon(w *strings.Builder, common *ssa.CallCommon, context ssa.Instruction) {
	if common.IsInvoke() {
		w.WriteString("Invoke " + c.NormalizeOperand(common.Value, context) + "." + common.Method.Name())
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
	visited := make(map[ssa.Value]bool)
	for {
		if visited[v] {
			break
		}
		visited[v] = true

		sub, ok := c.virtualSubstitutions[v]
		if !ok {
			break
		}

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
	case loop.SCEV:
		return operand.StringWithRenamer(c.renamerFunc())
	case *ssa.Const:
		if c.Policy.ShouldAbstract(operand, context) {
			return fmt.Sprintf("<%s_literal>", sanitizeType(operand.Type()))
		}
		if operand.Value == nil {
			return fmt.Sprintf("const(%s:nil)", sanitizeType(operand.Type()))
		}
		if operand.Value.Kind() == constant.String {
			return fmt.Sprintf("const(%q)", constant.StringVal(operand.Value))
		}
		return fmt.Sprintf("const(%s)", operand.Value.ExactString())
	case *ssa.Global:
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

	return strings.ReplaceAll(res, "\n", " ")
}
