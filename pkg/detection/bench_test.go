package detection

import (
	"fmt"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
)

func BenchmarkGenerateTopologyHash(b *testing.B) {
	topo := &topology.FunctionTopology{
		ParamCount:     2,
		ReturnCount:    1,
		BlockCount:     10,
		InstrCount:     50,
		LoopCount:      2,
		BranchCount:    3,
		CallSignatures: make(map[string]int),
	}

	// Populate with some call signatures
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("pkg.Func%d", i)
		topo.CallSignatures[key] = i % 5
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateTopologyHash(topo)
	}
}
