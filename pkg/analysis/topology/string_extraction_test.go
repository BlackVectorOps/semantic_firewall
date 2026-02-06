package topology_test

import (
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/testutil"
)

// TestStringExtraction verifies that string literals are extracted without quotes.
// This ensures that constant.StringVal is used instead of constant.ExactString.
func TestStringExtraction(t *testing.T) {
	t.Parallel()

	src := `package main
	func stringFunc() {
		println("raw_content")
	}`

	fn := testutil.CompileAndGetFunction(t, src, "stringFunc")
	topo := topology.ExtractTopology(fn)

	if topo == nil {
		t.Fatal("ExtractTopology returned nil")
	}

	expected := "raw_content"
	found := false
	for _, lit := range topo.StringLiterals {
		if lit == expected {
			found = true
		}
		if lit == `"`+expected+`"` {
			t.Errorf("String literal extracted with quotes: %s", lit)
		}
	}

	if !found {
		t.Errorf("Expected string literal %q not found. Got: %v", expected, topo.StringLiterals)
	}
}
