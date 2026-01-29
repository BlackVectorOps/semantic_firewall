package topology_test

import (
	"math"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/analysis/topology"
)

func TestCalculateEntropy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected float64
		epsilon  float64
	}{
		{"Empty", []byte{}, 0.0, 0.001},
		{"Zero Entropy", []byte{0, 0, 0, 0}, 0.0, 0.001},
		{"1 Bit Entropy", []byte{0, 1, 0, 1}, 1.0, 0.001},
		{"Max Entropy (16 bytes)", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, 4.0, 0.001},
		{"Text Profile", []byte("abcdefghijklmnopqrstuvwxyz"), 4.7, 0.1},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := topology.CalculateEntropy(tc.input)
			if math.Abs(got-tc.expected) > tc.epsilon {
				t.Errorf("got %f, want %f (±%f)", got, tc.expected, tc.epsilon)
			}
		})
	}
}

func TestClassifyEntropy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		score float64
		want  topology.EntropyClass
	}{
		{0.0, topology.EntropyLow},
		{4.0, topology.EntropyNormal},
		{7.0, topology.EntropyHigh},
		{8.0, topology.EntropyPacked},
	}

	for _, tc := range tests {
		if got := topology.ClassifyEntropy(tc.score); got != tc.want {
			t.Errorf("Score %f: got %v, want %v", tc.score, got, tc.want)
		}
	}
}
