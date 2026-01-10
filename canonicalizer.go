package semanticfw

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Transforms an SSA function into a deterministic string representation.
type Canonicalizer struct {
	Policy      LiteralPolicy
	StrictMode  bool
	registerMap map[ssa.Value]string
	blockMap    map[*ssa.BasicBlock]string
	regCounter  int
	output      strings.Builder
}

// Initializes a new instance of the normalization engine.
func NewCanonicalizer(policy LiteralPolicy) *Canonicalizer {
	return &Canonicalizer{
		Policy:      policy,
		StrictMode:  false,
		registerMap: make(map[ssa.Value]string),
		blockMap:    make(map[*ssa.BasicBlock]string),
	}
}

// Performs a DFS traversal prioritizing True branches to ensure stability.
func (c *Canonicalizer) deterministicTraversal(fn *ssa.Function) []*ssa.BasicBlock {
	var sortedBlocks []*ssa.BasicBlock
	if len(fn.Blocks) == 0 {
		return sortedBlocks
	}

	// BUG FIX: Defensive nil check for entry block
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

		succs := block.Succs
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

// Orchestrates the conversion of SSA blocks into canonical IR.
func (c *Canonicalizer) CanonicalizeFunction(fn *ssa.Function) string {
	if len(fn.Blocks) == 0 {
		return fmt.Sprintf("func%s (external)\n", sanitizeType(fn.Signature))
	}

	c.reset()

	for i, param := range fn.Params {
		c.normalizeValue(param, fmt.Sprintf("p%d", i))
	}
	for i, fv := range fn.FreeVars {
		c.normalizeValue(fv, fmt.Sprintf("fv%d", i))
	}

	sortedBlocks := c.deterministicTraversal(fn)

	for i, block := range sortedBlocks {
		c.blockMap[block] = fmt.Sprintf("b%d", i)
	}

	c.writeFunctionSignature(fn)

	for _, block := range sortedBlocks {
		if _, exists := c.blockMap[block]; exists {
			c.processBlock(block)
		}
	}

	return c.output.String()
}

func (c *Canonicalizer) reset() {
	c.registerMap = make(map[ssa.Value]string)
	c.blockMap = make(map[*ssa.BasicBlock]string)
	c.regCounter = 0
	c.output.Reset()
}

// Maps SSA values to stable register names.
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
	for _, instr := range block.Instrs {
		c.processInstruction(instr)
	}
}

func isCommutative(instr *ssa.BinOp) bool {
	switch instr.Op {
	case token.ADD:
		// BUG FIX: String concatenation is not commutative
		if basic, ok := instr.X.Type().Underlying().(*types.Basic); ok && (basic.Info()&types.IsString) != 0 {
			return false
		}
		return true
	case token.MUL, token.EQL, token.NEQ, token.AND, token.OR, token.XOR:
		return true
	default:
		return false
	}
}

// Dispatches instructions to their specific canonical handlers.
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
		if isCommutative(i) && normX > normY {
			rhs.WriteString(fmt.Sprintf("BinOp %s, %s, %s", i.Op.String(), normY, normX))
		} else {
			rhs.WriteString(fmt.Sprintf("BinOp %s, %s, %s", i.Op.String(), normX, normY))
		}
	case *ssa.UnOp:
		rhs.WriteString(fmt.Sprintf("UnOp %s, %s", i.Op.String(), c.normalizeOperand(i.X, instr)))
	case *ssa.Phi:
		c.writePhi(&rhs, i, instr)
	case *ssa.Alloc:
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
				rhs.WriteString(fmt.Sprintf("Alloca %s", typeRep))
			} else {
				rhs.WriteString(fmt.Sprintf("Alloca %s", sanitizeType(elemType)))
			}
		}
	case *ssa.Store:
		rhs.WriteString(fmt.Sprintf("Store %s, %s", c.normalizeOperand(i.Addr, instr), c.normalizeOperand(i.Val, instr)))
	case *ssa.If:
		isControlFlow = true
		rhs.WriteString(fmt.Sprintf("If %s, %s, %s", c.normalizeOperand(i.Cond, instr), c.blockMap[i.Block().Succs[0]], c.blockMap[i.Block().Succs[1]]))
	case *ssa.Jump:
		isControlFlow = true
		rhs.WriteString(fmt.Sprintf("Jump %s", c.blockMap[i.Block().Succs[0]]))
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
		// BUG FIX: Handle interface-to-interface conversions (e.g., io.Reader to interface{})
		rhs.WriteString(fmt.Sprintf("ChangeInterface %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.SliceToArrayPointer:
		// BUG FIX: Handle slice-to-array-pointer conversions (Go 1.20+)
		rhs.WriteString(fmt.Sprintf("SliceToArrayPointer %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.MultiConvert:
		// BUG FIX: Handle complex type conversions (Go 1.21+)
		rhs.WriteString(fmt.Sprintf("MultiConvert %s, %s", sanitizeType(i.Type()), c.normalizeOperand(i.X, instr)))
	case *ssa.DebugRef:
		// BUG FIX: Explicitly ignore DebugRef to avoid panics in StrictMode
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
		// BUG FIX: Only check Tuple if val.Type() is not nil to avoid panic
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

	// BUG FIX: Use SliceStable for deterministic output when representations are identical
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
	for j, val := range i.Edges {
		predBlock := i.Block().Preds[j]
		predID := c.blockMap[predBlock]
		if predID == "" {
			continue
		}
		idx, _ := strconv.Atoi(predID[1:])
		edges = append(edges, edge{predID: predID, predIndex: idx, value: c.normalizeOperand(val, instr)})
	}

	// BUG FIX: Use SliceStable
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
	switch operand := v.(type) {
	case *ssa.Const:
		if c.Policy.ShouldAbstract(operand, context) {
			return fmt.Sprintf("<%s_literal>", sanitizeType(operand.Type()))
		}
		if operand.Value == nil {
			return fmt.Sprintf("const(%s:nil)", sanitizeType(operand.Type()))
		}
		return fmt.Sprintf("const(%s)", operand.Value.ExactString())
	case *ssa.Global:
		return fmt.Sprintf("<global:%s>", sanitizeType(operand.Type()))
	case *ssa.Builtin:
		return fmt.Sprintf("<builtin:%s>", operand.Name())
	case *ssa.Function:
		if name, exists := c.registerMap[v]; exists {
			return name
		}
		// BUG FIX: Include the function name (e.g. parent$1) to distinguish closures
		// with identical signatures but different bodies.
		return fmt.Sprintf("<func_ref:%s:%s>", operand.Name(), sanitizeType(operand.Signature))
	default:
		return c.normalizeValue(v)
	}
}

func sanitizeType(t types.Type) string {
	if t == nil {
		return "<nil_type>"
	}

	// Handle Signatures explicitly to remove parameter names, ensuring
	// that renaming variables (e.g., 'b' -> 'buf') doesn't change the fingerprint.
	if sig, ok := t.(*types.Signature); ok {
		var params []string
		for i := 0; i < sig.Params().Len(); i++ {
			// BUG FIX: Handle variadic parameters properly by using "..." notation.
			paramType := sig.Params().At(i).Type()
			if sig.Variadic() && i == sig.Params().Len()-1 {
				if slice, ok := paramType.(*types.Slice); ok {
					elemStr := types.TypeString(slice.Elem(), func(p *types.Package) string {
						if p != nil {
							return p.Name()
						}
						return ""
					})
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

		// Ensure consistent formatting for results: func(...) (Results...)
		resStr := ""
		if len(results) > 0 {
			resStr = " (" + strings.Join(results, ", ") + ")"
		}

		return fmt.Sprintf("func(%s)%s", strings.Join(params, ", "), resStr)
	}

	return types.TypeString(t, func(p *types.Package) string {
		if p != nil {
			return p.Name()
		}
		return ""
	})
}
