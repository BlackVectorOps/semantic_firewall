package topology

import (
	"go/constant"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/loop"
)

// maxGuardBlocks bounds the guard analysis, which costs a graph walk per
// block that references a capability. Larger functions record no guards.
const maxGuardBlocks = 2000

// collectCapabilityGuards records, for each capability call target, the
// fewest conditional branches any of its references is control-dependent
// on: the conditions that decide whether that call runs. A reference with
// no guard at all records 0, and so does a target that runs on every path
// through the function, even when each of its references sits under a
// branch (the same call on both sides of an if). Loop conditions are not
// guards: they decide how often a call runs, not whether the caller may
// make it.
//
// Block b is control-dependent on a two-way branch in block a when b
// post-dominates one successor of a but not a itself: one outcome of the
// branch guarantees that b runs, the other does not. A block that calls a
// function that never returns (os.Exit, log.Fatal, a helper of the same
// package that always ends in one) ends the function, like a return or a
// panic. A branch on a constant is no guard: only the side it takes runs.
func collectCapabilityGuards(fn *ssa.Function, t *FunctionTopology, loops *loop.LoopInfo, nr noReturns) {
	if len(t.Capabilities) == 0 || len(fn.Blocks) > maxGuardBlocks {
		return
	}
	g := newFlowGraph(fn, loops, nr)

	// The live blocks that reference each capability, in block order.
	sites := make(map[string][]*ssa.BasicBlock)
	for _, b := range fn.Blocks {
		if !g.live[b.Index] {
			continue
		}
		for _, instr := range b.Instrs {
			for _, op := range instr.Operands(nil) {
				callee, ok := (*op).(*ssa.Function)
				if !ok {
					continue
				}
				// Capabilities holds package-level callees only: the key of
				// a closure or a package initializer never matches.
				pkgPath, recv, name, _ := calleeIdentity(callee)
				key := callTargetKey(pkgPath, recv, name)
				if _, sensitive := t.Capabilities[key]; !sensitive {
					continue
				}
				if s := sites[key]; len(s) == 0 || s[len(s)-1] != b {
					sites[key] = append(s, b)
				}
			}
		}
	}

	counts := make([]int, len(fn.Blocks))
	for i := range counts {
		counts[i] = -1
	}
	avoid := make([]bool, len(fn.Blocks))
	guardCount := func(b *ssa.BasicBlock) int {
		if n := counts[b.Index]; n >= 0 {
			return n
		}
		avoid[b.Index] = true
		escapes := g.escapesAvoiding(avoid)
		avoid[b.Index] = false
		n := 0
		for _, a := range fn.Blocks {
			succs := g.succs[a.Index]
			if len(succs) != 2 || !escapes[a.Index] || leavesLoop(loops, a, succs) {
				continue
			}
			if !escapes[succs[0].Index] || !escapes[succs[1].Index] {
				n++
			}
		}
		counts[b.Index] = n
		return n
	}

	t.CapabilityGuards = make(map[string]int, len(sites))
	for key, blocks := range sites {
		for _, b := range blocks {
			avoid[b.Index] = true
		}
		unavoidable := !g.escapesAvoiding(avoid)[0]
		for _, b := range blocks {
			avoid[b.Index] = false
		}
		if unavoidable {
			t.CapabilityGuards[key] = 0
			continue
		}
		least := guardCount(blocks[0])
		for _, b := range blocks[1:] {
			least = min(least, guardCount(b))
		}
		t.CapabilityGuards[key] = least
	}
}

// leavesLoop reports whether a, a block with the two successors succs, is
// the header of a loop whose branch leaves it: a loop condition. The first
// branch of a "for {}" body is the header too, but both of its sides stay
// in the loop.
func leavesLoop(loops *loop.LoopInfo, a *ssa.BasicBlock, succs []*ssa.BasicBlock) bool {
	l := loops.LoopMap[a]
	return l != nil && (!l.Blocks[succs[0]] || !l.Blocks[succs[1]])
}

// flowGraph is the control flow of a function as it can run: a branch on a
// constant has only the successor it takes, and blocks the entry cannot
// reach that way are not live.
type flowGraph struct {
	succs [][]*ssa.BasicBlock // live successors, by block index
	live  []bool              // reachable from the entry, by block index
	exits []*ssa.BasicBlock

	reached []bool // scratch space of escapesAvoiding
	stack   []*ssa.BasicBlock
}

func newFlowGraph(fn *ssa.Function, loops *loop.LoopInfo, nr noReturns) *flowGraph {
	n := len(fn.Blocks)
	g := &flowGraph{
		succs:   make([][]*ssa.BasicBlock, n),
		live:    make([]bool, n),
		reached: make([]bool, n),
	}
	for _, b := range fn.Blocks {
		g.succs[b.Index] = liveSuccs(b)
	}
	g.live[0] = true
	stack := []*ssa.BasicBlock{fn.Blocks[0]}
	for len(stack) > 0 {
		b := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, s := range g.succs[b.Index] {
			if !g.live[s.Index] {
				g.live[s.Index] = true
				stack = append(stack, s)
			}
		}
	}
	for _, b := range fn.Blocks {
		if g.live[b.Index] && (len(g.succs[b.Index]) == 0 || nr.calledIn(b)) {
			g.exits = append(g.exits, b)
		}
	}
	// A function that loops forever, a worker or a server, has blocks from
	// which no path returns, and without an exit nothing post-dominates
	// anything. The header of each loop that never ends acts as its exit
	// instead: each pass around the loop is a unit of work, and the
	// branches that decide what one pass does are its guards.
	canExit := append([]bool(nil), g.escapesAvoiding(nil)...)
	for _, l := range loops.Loops {
		if h := l.Header; g.live[h.Index] && !canExit[h.Index] {
			g.exits = append(g.exits, h)
		}
	}
	return g
}

// liveSuccs returns the successors of b that can run: both of a branch's,
// unless its condition is a constant.
func liveSuccs(b *ssa.BasicBlock) []*ssa.BasicBlock {
	cond, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If)
	if !ok {
		return b.Succs
	}
	c, ok := cond.Cond.(*ssa.Const)
	if !ok {
		return b.Succs
	}
	// A nil Value is the zero value, false.
	if c.Value != nil && constant.BoolVal(c.Value) {
		return b.Succs[:1]
	}
	return b.Succs[1:]
}

// escapesAvoiding returns, by block index, the live blocks from which some
// path reaches an exit without passing through a block avoid marks (avoid
// may be nil). A block it omits is post-dominated by the avoided blocks:
// every way out of the function runs one of them first. The result is
// scratch space, valid until the next call.
func (g *flowGraph) escapesAvoiding(avoid []bool) []bool {
	reached := g.reached
	clear(reached)
	stack := g.stack[:0]
	for _, b := range g.exits {
		if avoid == nil || !avoid[b.Index] {
			reached[b.Index] = true
			stack = append(stack, b)
		}
	}
	for len(stack) > 0 {
		b := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, p := range b.Preds {
			if reached[p.Index] || !g.live[p.Index] || (avoid != nil && avoid[p.Index]) || !g.edge(p, b) {
				continue
			}
			reached[p.Index] = true
			stack = append(stack, p)
		}
	}
	g.stack = stack
	return reached
}

// edge reports whether control can flow from p to its successor b.
func (g *flowGraph) edge(p, b *ssa.BasicBlock) bool {
	for _, s := range g.succs[p.Index] {
		if s == b {
			return true
		}
	}
	return false
}

// noReturns remembers which functions of the package being analyzed never
// return to their caller (see never).
type noReturns map[*ssa.Function]bool

// calledIn reports whether a block calls a function that never returns to
// its caller.
func (nr noReturns) calledIn(b *ssa.BasicBlock) bool {
	for _, instr := range b.Instrs {
		call, ok := instr.(*ssa.Call)
		if !ok {
			continue
		}
		callee := call.Call.StaticCallee()
		if callee == nil {
			continue
		}
		if callsKnownNoReturn(callee) || nr.never(callee, b.Parent()) {
			return true
		}
	}
	return false
}

// never reports whether callee, a function of caller's package, never
// returns: each of its blocks that returns calls a function isNoReturn
// lists (a die helper that prints and exits). The search goes no deeper,
// and never leaves the package, for the reason checksReached gives.
func (nr noReturns) never(callee, caller *ssa.Function) bool {
	if pkg := pkgOf(callee); pkg == nil || pkg != pkgOf(caller) || len(callee.Blocks) == 0 {
		return false
	}
	if never, ok := nr[callee]; ok {
		return never
	}
	never := true
	for _, b := range callee.Blocks {
		if _, ok := b.Instrs[len(b.Instrs)-1].(*ssa.Return); ok && !blockCallsKnownNoReturn(b) {
			never = false
			break
		}
	}
	nr[callee] = never
	return never
}

func blockCallsKnownNoReturn(b *ssa.BasicBlock) bool {
	for _, instr := range b.Instrs {
		if call, ok := instr.(*ssa.Call); ok {
			if callee := call.Call.StaticCallee(); callee != nil && callsKnownNoReturn(callee) {
				return true
			}
		}
	}
	return false
}

func callsKnownNoReturn(callee *ssa.Function) bool {
	pkgPath, recv, name, ok := calleeIdentity(callee)
	return ok && isNoReturn(pkgPath, recv, name)
}

func isNoReturn(pkgPath, recv, name string) bool {
	switch pkgPath {
	case "os":
		return recv == "" && name == "Exit"
	case "runtime":
		return recv == "" && name == "Goexit"
	case "log":
		// The package functions and *log.Logger, its only type, alike.
		switch name {
		case "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln":
			return true
		}
	case "testing":
		switch name {
		case "Fatal", "Fatalf", "FailNow", "Skip", "Skipf", "SkipNow":
			return true
		}
	}
	return false
}

// countErrorExits counts the two-way branches with exactly one side that
// ends in an error exit (see isErrorExit). These are the checks that stop
// a function when a condition fails: `if err != nil { return err }`, an
// authorization test that writes 403, a validation that panics.
func countErrorExits(fn *ssa.Function, nr noReturns) int {
	n := 0
	for _, b := range fn.Blocks {
		cond, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If)
		if !ok {
			continue // an If is the only terminator with two successors
		}
		if _, ok := cond.Cond.(*ssa.Const); ok {
			continue // only one side can run
		}
		if isErrorExit(b.Succs[0], cond, 0, nr) != isErrorExit(b.Succs[1], cond, 1, nr) {
			n++
		}
	}
	return n
}

// isErrorExit reports whether successor succ of the branch cond, followed
// through at most three unconditional jumps, ends the function with a
// failure: a panic, a call that never returns, an HTTP error response
// (http.Error, http.NotFound, or WriteHeader with a constant status of 400
// or more) or the return of a failure error (see isFailureError).
func isErrorExit(b *ssa.BasicBlock, cond *ssa.If, succ int, nr noReturns) bool {
	// A function with a defer keeps its results in locals: a return stores
	// them, runs the deferred calls and returns what it loads back. stored
	// holds the last value stored in each local on the way.
	var stored map[*ssa.Alloc]ssa.Value
	for hops := 0; hops < 4; hops++ {
		if nr.calledIn(b) || writesHTTPError(b) {
			return true
		}
		for _, instr := range b.Instrs {
			if st, ok := instr.(*ssa.Store); ok {
				if local, ok := st.Addr.(*ssa.Alloc); ok {
					if stored == nil {
						stored = make(map[*ssa.Alloc]ssa.Value)
					}
					stored[local] = st.Val
				}
			}
		}
		switch last := b.Instrs[len(b.Instrs)-1].(type) {
		case *ssa.Panic:
			return true
		case *ssa.Return:
			for _, r := range last.Results {
				if load, ok := r.(*ssa.UnOp); ok && load.Op == token.MUL {
					if v, ok := stored[localOf(load.X)]; ok {
						r = v
					}
				}
				if isErrorType(r.Type()) && isFailureError(r, cond, succ) {
					return true
				}
			}
			return false
		}
		if len(b.Succs) != 1 {
			return false
		}
		b = b.Succs[0]
	}
	return false
}

// localOf returns v as a local, or nil.
func localOf(v ssa.Value) *ssa.Alloc {
	local, _ := v.(*ssa.Alloc)
	return local
}

// isFailureError reports whether an error value returned on successor succ
// of cond is a failure rather than a passed-through result: a new error
// (errors.New, fmt.Errorf, errors.Join, a concrete error converted to
// error), a package-level error variable (a sentinel such as ErrNotFound),
// or the value cond just tested to be non-nil.
func isFailureError(v ssa.Value, cond *ssa.If, succ int) bool {
	switch v := v.(type) {
	case *ssa.Const:
		return false
	case *ssa.MakeInterface:
		return true
	case *ssa.UnOp:
		if _, ok := v.X.(*ssa.Global); ok && v.Op == token.MUL {
			return true
		}
	case *ssa.Call:
		if callee := v.Call.StaticCallee(); callee != nil {
			if pkgPath, recv, name, ok := calleeIdentity(callee); ok && recv == "" &&
				((pkgPath == "errors" && (name == "New" || name == "Join")) || (pkgPath == "fmt" && name == "Errorf")) {
				return true
			}
		}
	}
	test, ok := cond.Cond.(*ssa.BinOp)
	if !ok || (test.Op != token.NEQ && test.Op != token.EQL) {
		return false
	}
	other := test.Y
	if test.Y == v {
		other = test.X
	} else if test.X != v {
		return false
	}
	// v has an error type, and so has what it is compared with; a constant
	// of an interface type is nil.
	if _, ok := other.(*ssa.Const); !ok {
		return false
	}
	// "v != nil" holds on the true successor, "v == nil" fails on the false one.
	return (test.Op == token.NEQ) == (succ == 0)
}

func isErrorType(t types.Type) bool {
	return types.Identical(t, types.Universe.Lookup("error").Type())
}

func writesHTTPError(b *ssa.BasicBlock) bool {
	for _, instr := range b.Instrs {
		call, ok := instr.(*ssa.Call)
		if !ok {
			continue
		}
		if call.Call.IsInvoke() {
			if call.Call.Method.Name() == "WriteHeader" && len(call.Call.Args) == 1 {
				if c, ok := call.Call.Args[0].(*ssa.Const); ok {
					if intConst(c) >= 400 {
						return true
					}
				}
			}
		} else if callee := call.Call.StaticCallee(); callee != nil {
			if pkgPath, recv, name, ok := calleeIdentity(callee); ok && pkgPath == "net/http" && recv == "" &&
				(name == "Error" || name == "NotFound") {
				return true
			}
		}
	}
	return false
}
