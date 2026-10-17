package ir_test

import (
	"go/token"
	"go/types"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/ir"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/analysis/loop"
	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/testutil"
	"golang.org/x/tools/go/ssa"
)

func TestCanonicalizer_Policies(t *testing.T) {
	t.Parallel()

	src := `package main
		func check(x int) int {
			if x > 1000 { return 1 }
			return 0
		}`

	fn := testutil.CompileAndGetFunction(t, src, "check")

	tests := []struct {
		name       string
		policy     ir.LiteralPolicy
		mustMatch  []string
		mustNotHas []string
	}{
		{
			name:   "Default Policy",
			policy: ir.DefaultLiteralPolicy,
			mustMatch: []string{
				"<int_literal>", // 1000 abstracted
				"const(1)",      // Small return kept
			},
			mustNotHas: []string{"const(1000)"},
		},
		{
			name:   "KeepAll Policy",
			policy: ir.KeepAllLiteralsPolicy,
			mustMatch: []string{
				"const(1000)",
			},
			mustNotHas: []string{"<int_literal>"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := ir.NewCanonicalizer(tc.policy)
			defer ir.ReleaseCanonicalizer(c)

			out := c.CanonicalizeFunction(fn)

			for _, m := range tc.mustMatch {
				if !strings.Contains(out, m) {
					t.Errorf("Missing %q in IR", m)
				}
			}
			for _, m := range tc.mustNotHas {
				if strings.Contains(out, m) {
					t.Errorf("Forbidden %q found in IR", m)
				}
			}
		})
	}
}

// mockRecursiveSCEV implements ssa.Value and loop.SCEV to simulate recursive structures.
type mockRecursiveSCEV struct {
	target ssa.Value
}

func (m *mockRecursiveSCEV) String() string                       { return "mock" }
func (m *mockRecursiveSCEV) Name() string                         { return "mock" }
func (m *mockRecursiveSCEV) Type() types.Type                     { return types.Typ[types.Int] }
func (m *mockRecursiveSCEV) Parent() *ssa.Function                { return nil }
func (m *mockRecursiveSCEV) Referrers() *[]ssa.Instruction        { return nil }
func (m *mockRecursiveSCEV) Operands(r []*ssa.Value) []*ssa.Value { return nil }
func (m *mockRecursiveSCEV) Pos() token.Pos                       { return token.NoPos }
func (m *mockRecursiveSCEV) IsLoopInvariant(l *loop.Loop) bool    { return false }
func (m *mockRecursiveSCEV) EvaluateAt(k *big.Int, cache map[loop.SCEV]*big.Int) *big.Int {
	return nil
}
func (m *mockRecursiveSCEV) StringWithRenamer(r loop.Renamer) string {
	return "Rec(" + r(m.target) + ")"
}

func TestSecurity_RenamerDoS(t *testing.T) {
	t.Parallel()

	// Create a cyclic dependency in substitutions to test renamer safety
	c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(c)

	// Mock values.
	// We use a recursive mock to ensure the renamer function is called recursively,
	// triggering the stack depth check.
	mockA := &loop.SCEVConstant{Value: big.NewInt(1)}
	mockB := &mockRecursiveSCEV{target: mockA}

	// Inject cycle A -> B -> A
	c.ExportTest_SetSubstitution(mockA, mockB)

	renamer := c.ExportTest_RenamerFunc()

	done := make(chan string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- "panic"
			}
		}()
		// This triggers the cycle traversal
		done <- renamer(mockA)
	}()

	select {
	case res := <-done:
		if res == "panic" {
			t.Fatal("Renamer panicked")
		}
		if !strings.Contains(res, "<cycle>") {
			t.Errorf("Expected <cycle> detection in output, got %q", res)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Renamer timed out - likely infinite recursion (DoS)")
	}
}

func TestCanonicalizer_HoistSafety(t *testing.T) {
	t.Parallel()

	// Regression test: Ensure len() on mutable types (map, chan) is NOT hoisted
	// out of loops that might modify them.
	src := `package main
		func foo(m map[int]int) int {
			sum := 0
			for i := 0; i < 10; i++ {
				m[i] = i
				sum += len(m) // This must NOT be hoisted
			}
			return sum
		}`

	fn := testutil.CompileAndGetFunction(t, src, "foo")

	c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(c)

	out := c.CanonicalizeFunction(fn)

	lines := strings.Split(out, "\n")
	var loopHeaderIdx, lenCallIdx int
	loopFound, lenFound := false, false

	for i, line := range lines {
		if strings.Contains(line, "; LoopHeader") {
			loopHeaderIdx = i
			loopFound = true
		}
		if strings.Contains(line, "Call <builtin:len>") {
			lenCallIdx = i
			lenFound = true
		}
	}

	if !loopFound {
		t.Fatal("Failed to detect LoopHeader in canonical output")
	}
	if !lenFound {
		t.Fatal("Failed to find len() call in canonical output")
	}

	// If len() was hoisted, it would appear in the pre-header (before loop header).
	// We expect it inside the loop body, which is printed AFTER the header label.
	if lenCallIdx < loopHeaderIdx {
		t.Errorf("Security Flaw: len(map) was incorrectly hoisted out of the loop.\nOutput snippet:\n%s", out)
	}
}

func TestCanonicalizer_TripCountNaming(t *testing.T) {
	t.Parallel()

	// A trip count names values through the renamer, so a loop bounded by
	// parameter n reports it as p0, not by its source name.
	src := `package main
		func loop(n int) {
			for i := 0; i < n; i++ {}
		}`

	fn := testutil.CompileAndGetFunction(t, src, "loop")
	c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(c)

	out := c.CanonicalizeFunction(fn)

	_, trip, found := strings.Cut(out, "TripCount: ")
	if !found {
		t.Fatalf("no trip count computed for a counted loop:\n%s", out)
	}
	trip, _, _ = strings.Cut(trip, "\n")
	if !strings.Contains(trip, "p0(inv)") || strings.Contains(trip, "n(inv)") {
		t.Errorf("TripCount %q should name the bound as p0, not n", trip)
	}
}

// A Canonicalizer that did not come from AcquireCanonicalizer works too.
func TestCanonicalizer_ZeroValue(t *testing.T) {
	t.Parallel()
	fn := testutil.CompileAndGetFunction(t, `package main
		var g int
		func h() string { return "h" }
		func f(n int) string {
			s := ""
			for i := 0; i < n; i++ { s += "abc" + h() }
			g++
			return s
		}`, "f")

	pooled := ir.AcquireCanonicalizer(ir.DefaultLiteralPolicy)
	want := pooled.CanonicalizeFunction(fn)
	ir.ReleaseCanonicalizer(pooled)

	zero := &ir.Canonicalizer{Policy: ir.DefaultLiteralPolicy}
	if got := zero.CanonicalizeFunction(fn); got != want {
		t.Errorf("zero-value Canonicalizer:\n%s\nwant\n%s", got, want)
	}

	// NormalizeOperand on a fresh zero value, before any analysis, renders
	// every operand as a pooled Canonicalizer does.
	pooled = ir.AcquireCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(pooled)
	fresh := &ir.Canonicalizer{Policy: ir.DefaultLiteralPolicy}
	n := 0
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			for _, op := range instr.Operands(nil) {
				if *op == nil {
					continue
				}
				switch (*op).(type) {
				case *ssa.Const, *ssa.Global, *ssa.Function:
				default:
					continue
				}
				n++
				if got, want := fresh.NormalizeOperand(*op, instr), pooled.NormalizeOperand(*op, instr); got != want {
					t.Errorf("NormalizeOperand(%v) on a zero value = %q; want %q", *op, got, want)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no constant, global or function operands to compare")
	}
}

func TestCanonicalizer_KitchenSink(t *testing.T) {
	t.Parallel()

	// Comprehensive test case to exercise all instruction handlers.
	// NOTE: We introduce a variable 'res' that is assigned differently
	// in select branches to strictly force the generation of a Phi node.
	src := `package main
	
	func everything(ch chan int, m map[string]interface{}) interface{} {
		// Defer
		defer func() { recover() }()

		res := 0

		// Select
		select {
		case x := <-ch:
			// Map Update & Interface
			m["val"] = x
			res = x
		default:
			// MakeSlice & Go
			go func() { _ = make([]int, 10, 20) }()
			res = 1
		}

		// Type Assert
		if val, ok := m["val"].(int); ok {
			return val * 2
		}
		
		return res
	}`

	fn := testutil.CompileAndGetFunction(t, src, "everything")
	c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(c)

	out := c.CanonicalizeFunction(fn)

	expected := []string{
		"Defer",
		"RunDefers",
		"Select [non-blocking]",
		// "MakeSlice" - Removed because MakeSlice is in the closure, not main function
		"Go ", // "Go Invoke" removed as it's a closure call in this example
		"MapUpdate",
		"TypeAssert",
		"Extract", // For tuple extraction from map lookup/type assert
		"Phi",     // Likely generated for control flow merge
	}

	for _, exp := range expected {
		if !strings.Contains(out, exp) {
			t.Errorf("Missing expected instruction %q in output:\n%s", exp, out)
		}
	}
}

func TestCanonicalizer_DerivedInductionVariable(t *testing.T) {
	t.Parallel()

	// A value derived affinely from the loop counter (here i*2) must be
	// recognised as a scalar-evolution recurrence and virtualised, instead of
	// surviving as an opaque BinOp MUL. This is what lets loops that compute a
	// strided value two different ways canonicalize to the same fingerprint.
	src := `package main
	func derived(n int) int {
		total := 0
		for i := 0; i < n; i++ {
			total += i * 2
		}
		return total
	}`

	fn := testutil.CompileAndGetFunction(t, src, "derived")
	c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(c)

	out := c.CanonicalizeFunction(fn)

	// {start, +, step} notation is only produced by an SCEVAddRec.
	if !strings.Contains(out, ", +, ") {
		t.Errorf("expected an affine recurrence {start, +, step} in canonical IR:\n%s", out)
	}
	// The derived multiplication must not survive as an opaque operation.
	if strings.Contains(out, "BinOp *") {
		t.Errorf("derived induction variable left as opaque BinOp MUL:\n%s", out)
	}

	// Canonicalization must remain deterministic with the new virtualization.
	for i := 0; i < 5; i++ {
		c2 := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
		out2 := c2.CanonicalizeFunction(fn)
		ir.ReleaseCanonicalizer(c2)
		if out != out2 {
			t.Fatalf("derived-IV canonical IR is not stable across runs:\n%s\n--- vs ---\n%s", out, out2)
		}
	}
}

func TestCanonicalizer_LoopDepthLimit(t *testing.T) {
	t.Parallel()

	// Generate source with excessive loop nesting
	var sb strings.Builder
	sb.WriteString("package main\nfunc nested() {\n")
	depth := 80
	for i := 0; i < depth; i++ {
		sb.WriteString("for {\n")
	}
	for i := 0; i < depth; i++ {
		sb.WriteString("}\n")
	}
	sb.WriteString("}")

	fn := testutil.CompileAndGetFunction(t, sb.String(), "nested")
	c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(c)

	done := make(chan bool)
	go func() {
		c.CanonicalizeFunction(fn)
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Canonicalization timed out on deep loops - recursion limit failed")
	}
}

func TestCanonicalizer_SelectCaseOrdering(t *testing.T) {
	t.Parallel()

	// Test that select case reordering produces identical fingerprints.
	// This validates the stability fix for select statements where case
	// order is semantically neutral (Go randomly picks when multiple channels ready).

	// Version A: ch1 case first
	srcA := `package main
	func selectTest(ch1, ch2 chan int) int {
		select {
		case x := <-ch1:
			return x + 1
		case y := <-ch2:
			return y + 2
		default:
			return 0
		}
	}`

	// Version B: ch2 case first (semantically equivalent)
	srcB := `package main
	func selectTest(ch1, ch2 chan int) int {
		select {
		case y := <-ch2:
			return y + 2
		case x := <-ch1:
			return x + 1
		default:
			return 0
		}
	}`

	fnA := testutil.CompileAndGetFunction(t, srcA, "selectTest")
	fnB := testutil.CompileAndGetFunction(t, srcB, "selectTest")

	cA := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(cA)
	cB := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(cB)

	outA := cA.CanonicalizeFunction(fnA)
	outB := cB.CanonicalizeFunction(fnB)

	// Both should contain the sorted select representation
	if !strings.Contains(outA, "Select [non-blocking]") {
		t.Errorf("Expected Select instruction in output A:\n%s", outA)
	}
	if !strings.Contains(outB, "Select [non-blocking]") {
		t.Errorf("Expected Select instruction in output B:\n%s", outB)
	}

	// Extract the select lines and verify they match
	selectLineA := extractSelectLine(outA)
	selectLineB := extractSelectLine(outB)

	if selectLineA != selectLineB {
		t.Errorf("Select case ordering should produce identical canonical representations.\nVersion A: %s\nVersion B: %s", selectLineA, selectLineB)
	}
}

func extractSelectLine(ir string) string {
	for _, line := range strings.Split(ir, "\n") {
		if strings.Contains(line, "Select") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func TestCanonicalizer_RangeMapStability(t *testing.T) {
	t.Parallel()

	// Test that range over map produces consistent fingerprints.
	// The map iteration order is non-deterministic at runtime,
	// but the SSA structure should be deterministic.

	src := `package main
	func rangeMap(m map[string]int) int {
		sum := 0
		for k, v := range m {
			_ = k
			sum += v
		}
		return sum
	}`

	fn := testutil.CompileAndGetFunction(t, src, "rangeMap")
	c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(c)

	out := c.CanonicalizeFunction(fn)

	// Should have Range and Next instructions
	if !strings.Contains(out, "Range") {
		t.Errorf("Expected Range instruction in output:\n%s", out)
	}
	if !strings.Contains(out, "Next") {
		t.Errorf("Expected Next instruction in output:\n%s", out)
	}

	// Canonicalize the same function multiple times to ensure stability
	for i := 0; i < 5; i++ {
		c2 := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
		out2 := c2.CanonicalizeFunction(fn)
		ir.ReleaseCanonicalizer(c2)

		if out != out2 {
			t.Errorf("Iteration %d: Canonical IR is not stable across multiple canonicalizations.\nExpected:\n%s\nGot:\n%s", i, out, out2)
		}
	}
}

func TestCanonicalizer_BlockOrderingStability(t *testing.T) {
	t.Parallel()

	// Test that blocks are ordered deterministically even when there
	// are multiple branches from a single point (e.g., type switch).

	src := `package main
	func typeSwitch(x interface{}) string {
		switch v := x.(type) {
		case int:
			return "int"
		case string:
			return v
		case bool:
			if v {
				return "true"
			}
			return "false"
		default:
			return "unknown"
		}
	}`

	fn := testutil.CompileAndGetFunction(t, src, "typeSwitch")

	// Run canonicalization multiple times
	var outputs []string
	for i := 0; i < 5; i++ {
		c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
		out := c.CanonicalizeFunction(fn)
		ir.ReleaseCanonicalizer(c)
		outputs = append(outputs, out)
	}

	// All outputs should be identical
	for i := 1; i < len(outputs); i++ {
		if outputs[0] != outputs[i] {
			t.Errorf("Block ordering not stable. Run 0 differs from run %d.\nRun 0:\n%s\nRun %d:\n%s",
				i, outputs[0], i, outputs[i])
		}
	}
}

func TestCanonicalizer_HoistSafety_Chan(t *testing.T) {
	t.Parallel()

	// Test len(chan) and cap(chan) are not hoisted.
	src := `package main
		func foo(c chan int) int {
			sum := 0
			for i := 0; i < 10; i++ {
				c <- i
				sum += len(c) // This must NOT be hoisted
				sum += cap(c) // This must NOT be hoisted
			}
			return sum
		}`

	fn := testutil.CompileAndGetFunction(t, src, "foo")

	c := ir.NewCanonicalizer(ir.DefaultLiteralPolicy)
	defer ir.ReleaseCanonicalizer(c)

	out := c.CanonicalizeFunction(fn)

	lines := strings.Split(out, "\n")
	var loopHeaderIdx int
	var lenCallIdx int = -1
	var capCallIdx int = -1
	loopFound := false

	for i, line := range lines {
		if strings.Contains(line, "; LoopHeader") {
			loopHeaderIdx = i
			loopFound = true
		}
		if strings.Contains(line, "Call <builtin:len>") {
			lenCallIdx = i
		}
		if strings.Contains(line, "Call <builtin:cap>") {
			capCallIdx = i
		}
	}

	if !loopFound {
		t.Fatal("Failed to detect LoopHeader in canonical output")
	}

	if lenCallIdx == -1 {
		t.Fatal("Failed to find len() call in canonical output")
	}
	if capCallIdx == -1 {
		t.Fatal("Failed to find cap() call in canonical output")
	}

	// If len() or cap() was hoisted, it would appear in the pre-header (before loop header).
	if lenCallIdx < loopHeaderIdx {
		t.Errorf("Security Flaw: len(chan) was incorrectly hoisted out of the loop.")
	}
	if capCallIdx < loopHeaderIdx {
		t.Errorf("Security Flaw: cap(chan) was incorrectly hoisted out of the loop.")
	}
}
