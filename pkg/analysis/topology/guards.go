package topology

import (
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/analysis/loop"
)

// maxGuardBlocks bounds the guard analysis, which costs a graph walk per
// block that references a capability. Larger functions record no guards.
const maxGuardBlocks = 2000

// collectCapabilityGuards records, for each capability call target, the
// fewest conditional branches any of its references is control-dependent
// on: the conditions that decide whether that call runs. A reference with
// no guard at all records 0. Loop conditions are not guards: they decide
// how often a call runs, not whether the caller may make it.
//
// Block b is control-dependent on a two-way branch in block a when b
// post-dominates one successor of a but not a itself: one outcome of the
// branch guarantees that b runs, the other does not. A block that calls a
// function that never returns (os.Exit, log.Fatal) ends the function, like
// a return or a panic.
func collectCapabilityGuards(fn *ssa.Function, t *FunctionTopology, loops *loop.LoopInfo) {
	if len(t.Capabilities) == 0 || len(fn.Blocks) > maxGuardBlocks {
		return
	}
	headers := make(map[*ssa.BasicBlock]bool)
	var walk func([]*loop.Loop)
	walk = func(ls []*loop.Loop) {
		for _, l := range ls {
			headers[l.Header] = true
			walk(l.Children)
		}
	}
	if loops != nil {
		walk(loops.Loops)
	}

	exits := make(map[*ssa.BasicBlock]bool)
	for _, b := range fn.Blocks {
		if len(b.Succs) == 0 || callsNoReturn(b) {
			exits[b] = true
		}
	}

	counts := make(map[*ssa.BasicBlock]int)
	guardCount := func(b *ssa.BasicBlock) int {
		if n, ok := counts[b]; ok {
			return n
		}
		escapes := escapesAvoiding(fn, exits, b)
		n := 0
		for _, a := range fn.Blocks {
			if a == b || len(a.Succs) != 2 || headers[a] || !escapes[a] {
				continue
			}
			for _, s := range a.Succs {
				if s == b || !escapes[s] {
					n++
					break
				}
			}
		}
		counts[b] = n
		return n
	}

	t.CapabilityGuards = make(map[string]int)
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			for _, op := range instr.Operands(nil) {
				if op == nil || *op == nil {
					continue
				}
				callee, ok := (*op).(*ssa.Function)
				if !ok || callee.Parent() != nil {
					continue
				}
				pkgPath, recv, name, ok := calleeIdentity(callee)
				if !ok {
					continue
				}
				key := callTargetKey(pkgPath, recv, name)
				if _, sensitive := t.Capabilities[key]; !sensitive {
					continue
				}
				n := guardCount(b)
				if prev, seen := t.CapabilityGuards[key]; !seen || n < prev {
					t.CapabilityGuards[key] = n
				}
			}
		}
	}
}

// escapesAvoiding returns the blocks from which some path reaches an exit
// without passing through avoid. A block it omits is post-dominated by
// avoid: every way out of the function runs avoid first.
func escapesAvoiding(fn *ssa.Function, exits map[*ssa.BasicBlock]bool, avoid *ssa.BasicBlock) map[*ssa.BasicBlock]bool {
	reached := make(map[*ssa.BasicBlock]bool)
	var queue []*ssa.BasicBlock
	for b := range exits {
		if b != avoid {
			reached[b] = true
			queue = append(queue, b)
		}
	}
	for len(queue) > 0 {
		b := queue[0]
		queue = queue[1:]
		for _, p := range b.Preds {
			if p == avoid || reached[p] {
				continue
			}
			reached[p] = true
			queue = append(queue, p)
		}
	}
	return reached
}

// callsNoReturn reports whether a block calls a function that never
// returns to its caller.
func callsNoReturn(b *ssa.BasicBlock) bool {
	for _, instr := range b.Instrs {
		call, ok := instr.(*ssa.Call)
		if !ok {
			continue
		}
		callee := call.Call.StaticCallee()
		if callee == nil {
			continue
		}
		pkgPath, recv, name, ok := calleeIdentity(callee)
		if ok && isNoReturn(pkgPath, recv, name) {
			return true
		}
	}
	return false
}

func isNoReturn(pkgPath, recv, name string) bool {
	switch pkgPath {
	case "os":
		return recv == "" && name == "Exit"
	case "runtime":
		return recv == "" && name == "Goexit"
	case "log":
		if recv == "" || recv == "Logger" {
			switch name {
			case "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln":
				return true
			}
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
func countErrorExits(fn *ssa.Function) int {
	n := 0
	for _, b := range fn.Blocks {
		cond, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If)
		if !ok || len(b.Succs) != 2 {
			continue
		}
		if isErrorExit(b.Succs[0], cond, 0) != isErrorExit(b.Succs[1], cond, 1) {
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
func isErrorExit(b *ssa.BasicBlock, cond *ssa.If, succ int) bool {
	for hops := 0; b != nil && hops < 4; hops++ {
		if callsNoReturn(b) || writesHTTPError(b) {
			return true
		}
		switch last := b.Instrs[len(b.Instrs)-1].(type) {
		case *ssa.Panic:
			return true
		case *ssa.Return:
			for _, r := range last.Results {
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
	if c, ok := other.(*ssa.Const); !ok || !c.IsNil() {
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
					if v, exact := intConst(c); exact && v >= 400 {
						return true
					}
				}
			}
			continue
		}
		if callee := call.Call.StaticCallee(); callee != nil {
			if pkgPath, recv, name, ok := calleeIdentity(callee); ok && pkgPath == "net/http" && recv == "" &&
				(name == "Error" || name == "NotFound") {
				return true
			}
		}
	}
	return false
}
