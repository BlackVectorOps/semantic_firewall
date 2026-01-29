package topology_test

import (
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
)

func BenchmarkEntropyCalculation(b *testing.B) {
	data := make([]byte, 10240) // 10KB
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = topology.CalculateEntropy(data)
	}
}
