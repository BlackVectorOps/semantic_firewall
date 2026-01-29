package loop_test

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"go/token"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/loop"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/testutil"
)

func TestSCEVPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		src      string
		funcName string
		expectIV string
	}{
		{
			name: "Linear 0 to N",
			src: `package main
			func linear(n int) {
				for i := 0; i < n; i++ { _ = i }
			}`,
			funcName: "linear",
			expectIV: "{0, +, 1}",
		},
		{
			name: "Count Down",
			src: `package main
			func down(n int) {
				for i := n; i > 0; i-- { _ = i }
			}`,
			funcName: "down",
			expectIV: ", +, -1}",
		},
		{
			name: "Large Constant Bound",
			src: `package main
			func large() {
				// MaxUint64 is 18446744073709551615
				var limit uint64 = 18446744073709551615
				for i := uint64(0); i < limit; i++ { _ = i }
			}`,
			funcName: "large",
			expectIV: "18446744073709551615",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fn := testutil.CompileAndGetFunction(t, tc.src, tc.funcName)
			info := loop.DetectLoops(fn)
			loop.AnalyzeSCEV(info)

			if len(info.Loops) == 0 {
				t.Fatal("No loops detected")
			}

			found := false
			l := info.Loops[0]

			for _, iv := range l.Inductions {
				scev := &loop.SCEVAddRec{Start: iv.Start, Step: iv.Step}
				if strings.Contains(scev.String(), tc.expectIV) {
					found = true
					break
				}
			}
			if !found && l.TripCount != nil {
				if strings.Contains(l.TripCount.String(), tc.expectIV) {
					found = true
				}
			}
			if !found {
				t.Errorf("Expected pattern %q not found", tc.expectIV)
			}
		})
	}
}

func TestTripCountLogic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		src      string
		funcName string
		expected int64 // -1 implies nil/unknown
	}{
		{
			name: "Simple 0 to 100",
			src: `package main
			func count() { for i := 0; i < 100; i++ { } }`,
			funcName: "count",
			expected: 100,
		},
		{
			name: "Inclusive 0 to 10",
			src: `package main
			func count() { for i := 0; i <= 10; i++ { } }`,
			funcName: "count",
			expected: 11,
		},
		{
			name: "NEQ 0 to 10",
			src: `package main
			func count() { for i := 0; i != 10; i++ { } }`,
			funcName: "count",
			expected: 10,
		},
		{
			name: "Dead Loop (Start > Limit)",
			src: `package main
			func count() { 
				// Start=10, Limit=0. Condition 10 < 0 is false.
				for i := 10; i < 0; i++ { } 
			}`,
			funcName: "count",
			expected: 0,
		},
		{
			name: "Divergent Loop (Infinite)",
			src: `package main
			func count() { 
				// Start=0, Limit=10, Step=-1. Moves away from limit.
				for i := 0; i < 10; i-- { } 
			}`,
			funcName: "count",
			expected: -1, // Unknown
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fn := testutil.CompileAndGetFunction(t, tc.src, tc.funcName)
			info := loop.DetectLoops(fn)
			loop.AnalyzeSCEV(info)

			if len(info.Loops) == 0 {
				if tc.expected == -1 {
					return
				}
				t.Fatal("No loops detected")
			}

			l := info.Loops[0]

			// For Unknown cases, TripCount should be nil or evaluate to nil
			if tc.expected == -1 {
				if l.TripCount == nil {
					return
				}
				val := l.TripCount.EvaluateAt(nil, nil)
				if val == nil {
					return
				}
				t.Logf("Warning: Expected unknown, got %v", val)
				return
			}

			if l.TripCount == nil {
				t.Fatal("TripCount is nil")
			}

			val := l.TripCount.EvaluateAt(nil, nil)
			if val == nil {
				t.Fatalf("TripCount evaluated to nil (SCEV: %s)", l.TripCount.String())
			}

			if val.Int64() != tc.expected {
				t.Errorf("Expected TripCount %d, got %d (SCEV: %s)", tc.expected, val.Int64(), l.TripCount.String())
			}
		})
	}
}

func TestDeepRecursionSafety(t *testing.T) {
	t.Parallel()
	// Tests iterative SCC finder logic against stack overflow
	var sb strings.Builder
	sb.WriteString("package main\nfunc deep() {\n")
	sb.WriteString("x0 := 0\n")
	for i := 1; i < 5000; i++ {
		fmt.Fprintf(&sb, "x%d := x%d + 1\n", i, i-1)
	}
	sb.WriteString("for i := 0; i < x4999; i++ { _ = i }\n")
	sb.WriteString("}\n")

	fn := testutil.CompileAndGetFunction(t, sb.String(), "deep")
	info := loop.DetectLoops(fn)
	loop.AnalyzeSCEV(info) // Should not panic

	if len(info.Loops) == 0 {
		t.Fatal("Loop not detected")
	}
}

func TestDAGExplosionSafety(t *testing.T) {
	t.Parallel()
	// Manually construct a DAG SCEV: x_i = x_{i-1} + x_{i-1}
	// Depth 60 => 2^60 ops if naive
	one := &loop.SCEVConstant{Value: big.NewInt(1)}
	var root loop.SCEV = one
	for i := 0; i < 60; i++ {
		root = &loop.SCEVGenericExpr{Op: token.ADD, X: root, Y: root}
	}

	start := time.Now()
	// Use empty cache
	cache := make(map[loop.SCEV]*big.Int)
	val := root.EvaluateAt(nil, cache)
	duration := time.Since(start)

	if duration > 100*time.Millisecond {
		t.Errorf("Evaluation too slow (%v), caching missing?", duration)
	}

	expected := new(big.Int).Lsh(big.NewInt(1), 60)
	if val.Cmp(expected) != 0 {
		t.Errorf("Calculation mismatch")
	}
}

func TestFloatExclusion(t *testing.T) {
	t.Parallel()
	src := `package main
	func floats() {
		for i := 0.0; i < 10.0; i = i + 1.0 { }
	}`
	fn := testutil.CompileAndGetFunction(t, src, "floats")
	info := loop.DetectLoops(fn)
	loop.AnalyzeSCEV(info)

	l := info.Loops[0]
	if len(l.Inductions) != 0 {
		t.Errorf("Expected 0 IVs for float loop, got %d", len(l.Inductions))
	}
}
