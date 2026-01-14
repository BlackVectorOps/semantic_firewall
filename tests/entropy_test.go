package semanticfw_test

import (
	"math"
	"testing"

	sfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected float64
		epsilon  float64 // tolerance for floating point comparison
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: 0.0,
			epsilon:  0.001,
		},
		{
			name:     "single byte repeated",
			input:    []byte{0x00, 0x00, 0x00, 0x00},
			expected: 0.0, // No randomness
			epsilon:  0.001,
		},
		{
			name:     "two distinct bytes equal frequency",
			input:    []byte{0x00, 0x01, 0x00, 0x01},
			expected: 1.0, // log2(2) = 1
			epsilon:  0.001,
		},
		{
			name:     "all unique bytes (max entropy sample)",
			input:    []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			expected: 4.0, // log2(16) = 4
			epsilon:  0.001,
		},
		{
			name:     "typical code - lowercase alphabet",
			input:    []byte("abcdefghijklmnopqrstuvwxyz"),
			expected: 4.7, // Approximate
			epsilon:  0.1,
		},
		{
			name:     "high entropy random-looking",
			input:    make256UniqueBytes(),
			expected: 8.0, // Maximum entropy
			epsilon:  0.001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sfw.CalculateEntropy(tt.input)
			if math.Abs(got-tt.expected) > tt.epsilon {
				t.Errorf("CalculateEntropy() = %v, want %v (±%v)", got, tt.expected, tt.epsilon)
			}
		})
	}
}

func make256UniqueBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestClassifyEntropy(t *testing.T) {
	tests := []struct {
		entropy  float64
		expected sfw.EntropyClass
	}{
		{0.0, sfw.EntropyLow},
		{3.9, sfw.EntropyLow},
		{4.0, sfw.EntropyNormal},
		{5.5, sfw.EntropyNormal},
		{6.4, sfw.EntropyNormal},
		{6.5, sfw.EntropyHigh},
		{7.0, sfw.EntropyHigh},
		{7.4, sfw.EntropyHigh},
		{7.5, sfw.EntropyPacked},
		{8.0, sfw.EntropyPacked},
	}

	for _, tt := range tests {
		got := sfw.ClassifyEntropy(tt.entropy)
		if got != tt.expected {
			t.Errorf("ClassifyEntropy(%v) = %v, want %v", tt.entropy, got, tt.expected)
		}
	}
}

func TestEntropyMatch(t *testing.T) {
	tests := []struct {
		e1, e2, tolerance float64
		expected          bool
	}{
		{5.0, 5.0, 0.5, true},
		{5.0, 5.4, 0.5, true},
		{5.0, 5.5, 0.5, true},
		{5.0, 5.6, 0.5, false},
		{5.0, 4.4, 0.5, false},
		{7.5, 7.8, 0.5, true},
	}

	for _, tt := range tests {
		got := sfw.EntropyMatch(tt.e1, tt.e2, tt.tolerance)
		if got != tt.expected {
			t.Errorf("EntropyMatch(%v, %v, %v) = %v, want %v", tt.e1, tt.e2, tt.tolerance, got, tt.expected)
		}
	}
}

func TestCalculateEntropyProfile(t *testing.T) {
	// Test with typical code-like content
	bodyBytes := []byte(`
		func main() {
			fmt.Println("Hello, World!")
			for i := 0; i < 10; i++ {
				doSomething(i)
			}
		}
	`)
	stringLiterals := []string{"Hello, World!", "error: something went wrong"}

	profile := sfw.CalculateEntropyProfile(bodyBytes, stringLiterals)

	// Verify the entropy is within normal code range
	if profile.Classification != sfw.EntropyNormal {
		t.Errorf("Expected NORMAL classification for typical code, got %v (entropy: %v)",
			profile.Classification, profile.Overall)
	}

	// Verify string literal entropy is calculated
	if profile.StringLiteralEntropy == 0 {
		t.Error("Expected non-zero string literal entropy")
	}
}

func TestEntropyClassString(t *testing.T) {
	tests := []struct {
		class    sfw.EntropyClass
		expected string
	}{
		{sfw.EntropyLow, "LOW"},
		{sfw.EntropyNormal, "NORMAL"},
		{sfw.EntropyHigh, "HIGH"},
		{sfw.EntropyPacked, "PACKED"},
		{sfw.EntropyClass(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.class.String(); got != tt.expected {
			t.Errorf("EntropyClass(%d).String() = %v, want %v", tt.class, got, tt.expected)
		}
	}
}
