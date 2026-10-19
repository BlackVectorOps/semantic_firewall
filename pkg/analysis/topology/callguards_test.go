package topology_test

import (
	"testing"

	"golang.org/x/tools/go/ssa"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/analysis/topology"
)

// CallGuards analyzes a function of up to 2000 blocks, as CapabilityGuards
// does, and refuses a larger one.
func TestCallGuards_BlockLimit(t *testing.T) {
	fns := functions(t, manyBranches(true, 998), manyBranches(false, 1001))
	for i, c := range []struct {
		blocks int
		ok     bool
	}{{2000, true}, {2003, false}} {
		fn := fns[i]
		if len(fn.Blocks) != c.blocks {
			t.Fatalf("fixture has %d blocks; want %d", len(fn.Blocks), c.blocks)
		}
		var remove *ssa.Function
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if call, ok := instr.(*ssa.Call); ok && call.Call.StaticCallee() != nil && call.Call.StaticCallee().Name() == "Remove" {
					remove = call.Call.StaticCallee()
				}
			}
		}
		if _, ok := topology.CallGuards(fn, remove); ok != c.ok {
			t.Errorf("%d blocks: CallGuards ok = %v; want %v", c.blocks, ok, c.ok)
		}
	}
}

// CallGuards counts the guards of F's calls to g as CapabilityGuards counts
// a capability's.
func TestCallGuards(t *testing.T) {
	cases := []struct {
		name, body string
		want       int
		ok         bool
	}{
		{"unconditional", "func F(x bool) { g() }", 0, true},
		{"guarded", "func F(x bool) { if x { g() } }", 1, true},
		{"early return", "func F(x bool) { if !x { return }; g() }", 1, true},
		{"nested: direct dependence only", "func F(a, b bool) { if a { if b { g() } } }", 1, true},
		{"either condition", "func F(a, b bool) { if a || b { g() } }", 2, true},
		{"both sides of a branch", "func F(x bool) { if x { g() } else { g() } }", 0, true},
		{"loop condition", "func F(n int) { for i := 0; i < n; i++ { g() } }", 0, true},
		{"fewest of two calls", "func F(a, b bool) { if a || b { g() }; if !a { return }; g() }", 1, true},
		{"constant branch", "func F() { if true { g() } }", 0, true},
		{"not referenced", "func F(x bool) { _ = x }", 0, false},
		{"fewer guards on the earlier call", "func F(a, b bool) { if !a { return }; g(); if a || b { g() } }", 1, true},
		{"other callees do not count", "func F(x bool) { h(); if x { g() } }", 1, true},
		{"only other callees", "func F(x bool) { if x { h() } }", 0, false},
	}
	srcs := make([]string, len(cases))
	for i, c := range cases {
		srcs[i] = "package main\nfunc g() {}\nfunc h() {}\n" + c.body + "\nfunc main() {}\n"
	}
	for i, fn := range functions(t, srcs...) {
		c := cases[i]
		n, ok := topology.CallGuards(fn, fn.Pkg.Func("g"))
		if n != c.want || ok != c.ok {
			t.Errorf("%s: CallGuards = %d, %v; want %d, %v", c.name, n, ok, c.want, c.ok)
		}
	}
}

func TestCallGuards_NoFunction(t *testing.T) {
	fn := functions(t, "package main\nfunc g() {}\nfunc F() { g() }\nfunc main() {}\n")[0]
	if _, ok := topology.CallGuards(nil, fn); ok {
		t.Error("CallGuards(nil, g) reported a reference")
	}
	if _, ok := topology.CallGuards(fn, nil); ok {
		t.Error("CallGuards(F, nil) reported a reference")
	}
}
