package topology_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/testutil"
)

func TestExtractTopology(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		src         string
		funcName    string
		wantLoops   int
		wantStrings []string
		wantCalls   []string
		wantParams  []string // To verify type normalization
		wantFlags   map[string]bool
	}{
		{
			name: "Control Flow",
			src: `package main
				func loops() {
					for i := 0; i < 10; i++ { println(i) }
				}`,
			funcName:  "loops",
			wantLoops: 1,
			wantCalls: []string{"builtin:println"},
		},
		{
			name: "Network & Strings",
			src: `package main
				import "net"
				func connect() {
					net.Dial("tcp", "127.0.0.1")
				}`,
			funcName:    "connect",
			wantStrings: []string{"127.0.0.1", "tcp"},
			wantCalls:   []string{"net.Dial"},
		},
		{
			// Bug Verification: Loops in closures must not be counted in parent
			name: "Nested Loop Isolation",
			src: `package main
				func scope() {
					_ = func() {
						for i := 0; i < 10; i++ {}
					}
				}`,
			funcName:  "scope",
			wantLoops: 0,
		},
		{
			// Bug Verification: Pointer types should not lose '*' when normalized
			name: "Pointer Type Normalization",
			src: `package main
				import "net/http"
				func handle(req *http.Request) {}`,
			funcName:   "handle",
			wantParams: []string{"*http.Request"},
		},
		{
			// Bug Verification: Go/Defer interface methods
			name: "Concurrent Interface",
			src: `package main
				type Runner interface { Run() }
				func exec(r Runner) {
					go r.Run()
					defer func() { recover() }()
				}`,
			funcName: "exec",
			wantCalls: []string{
				// Interface methods via 'go' are "invoke:ReceiverType.Method"
				// Note: testutil may map types to "testmod" package.
				"go:invoke:testmod.Runner.Run",
				"defer:closure:func()",
			},
			wantFlags: map[string]bool{
				"HasGo":    true,
				"HasDefer": true,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fn := testutil.CompileAndGetFunction(t, tc.src, tc.funcName)
			topo := topology.ExtractTopology(fn)

			if topo == nil {
				t.Fatal("ExtractTopology returned nil")
			}

			if topo.LoopCount != tc.wantLoops {
				t.Errorf("LoopCount: got %d, want %d", topo.LoopCount, tc.wantLoops)
			}

			for _, s := range tc.wantStrings {
				found := false
				for _, lit := range topo.StringLiterals {
					if lit == s {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Missing string literal %q", s)
				}
			}

			for _, call := range tc.wantCalls {
				found := false
				for sig := range topo.CallSignatures {
					if strings.Contains(sig, call) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Missing call signature %q. Available: %v", call, topo.CallSignatures)
				}
			}

			if len(tc.wantParams) > 0 {
				for i, want := range tc.wantParams {
					if i < len(topo.ParamTypes) && topo.ParamTypes[i] != want {
						t.Errorf("ParamType[%d]: got %q, want %q", i, topo.ParamTypes[i], want)
					}
				}
			}

			if tc.wantFlags != nil {
				if tc.wantFlags["HasGo"] && !topo.HasGo {
					t.Error("Expected HasGo to be true")
				}
				if tc.wantFlags["HasDefer"] && !topo.HasDefer {
					t.Error("Expected HasDefer to be true")
				}
			}
		})
	}
}

// TestASTScopeLeak ensures that the AST fallback loop counting does not
// incorrectly count loops inside closures/anonymous functions.
func TestASTScopeLeak(t *testing.T) {
	t.Parallel()

	src := `package main
	func parent() {
		// Parent has NO loop
		_ = func() {
			// Child has a loop
			for i := 0; i < 10; i++ {}
		}
	}`

	fn := testutil.CompileAndGetFunction(t, src, "parent")
	topo := topology.ExtractTopology(fn)

	// Parent should have 0 loops. If AST leaks scope, it will have 1.
	if topo.LoopCount != 0 {
		t.Errorf("Scope Leak: counted loops from nested closure. Got %d, want 0", topo.LoopCount)
	}
}

// TestFuzzyHashDistinction ensures that functions with 0 branches (linear)
// and 1 branch (single if) generate different fuzzy hashes.
func TestFuzzyHashDistinction(t *testing.T) {
	t.Parallel()

	srcLinear := `package main
	func linear() {
		println("straight line")
	}`

	srcBranched := `package main
	func branched(b bool) {
		if b {
			println("branch")
		}
	}`

	srcBranched2 := `package main
	func branched2(b bool, c bool) {
		if b {
			println("branch 1")
		}
		if c {
			println("branch 2")
		}
	}`

	fnLinear := testutil.CompileAndGetFunction(t, srcLinear, "linear")
	fnBranched := testutil.CompileAndGetFunction(t, srcBranched, "branched")
	fnBranched2 := testutil.CompileAndGetFunction(t, srcBranched2, "branched2")

	topoLinear := topology.ExtractTopology(fnLinear)
	topoBranched := topology.ExtractTopology(fnBranched)
	topoBranched2 := topology.ExtractTopology(fnBranched2)

	// Linear: 0 branches -> BR0
	if !strings.Contains(topoLinear.FuzzyHash, "BR0") {
		t.Errorf("Linear code hash should contain BR0, got %q", topoLinear.FuzzyHash)
	}

	// Single If: 1 branch -> BR1
	if !strings.Contains(topoBranched.FuzzyHash, "BR1") {
		t.Errorf("Branched code (1 if) hash should contain BR1, got %q", topoBranched.FuzzyHash)
	}

	// Two Ifs: 2 branches -> BR2
	if !strings.Contains(topoBranched2.FuzzyHash, "BR2") {
		t.Errorf("Branched code (2 ifs) hash should contain BR2, got %q", topoBranched2.FuzzyHash)
	}

	if topoLinear.FuzzyHash == topoBranched.FuzzyHash {
		t.Errorf("Fuzzy Hash Collision: Linear and Branched code produced same hash %q", topoLinear.FuzzyHash)
	}
}

// TestConcurrencyLimits ensures that setting limits concurrently with reading them works safely.
func TestConcurrencyLimits(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			topology.SetTopologyLimits(1024+i, 2048+i)
		}
	}()

	// Reader (simulated via Extraction)
	go func() {
		defer wg.Done()
		src := `package main; func test() { s := "hello"; _ = s }`
		fn := testutil.CompileAndGetFunction(t, src, "test")
		for i := 0; i < 100; i++ {
			_ = topology.ExtractTopology(fn)
		}
	}()

	wg.Wait()
}

func TestTopologySimilarity_Variant(t *testing.T) {
	// Verifies the Dice coefficient fix
	t.Parallel()
	t1 := &topology.FunctionTopology{ParamTypes: []string{"int"}}
	t2 := &topology.FunctionTopology{ParamTypes: []string{"int", "string"}}

	score := topology.TopologySimilarity(t1, t2)
	// 2*1 / (1+2) = 0.66
	if score < 0.5 {
		t.Errorf("Similarity score too low: %f. Dice coefficient logic failed.", score)
	}
}
