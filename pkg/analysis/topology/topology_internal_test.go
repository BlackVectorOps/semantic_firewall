package topology

import (
	"bytes"
	"testing"
)

func TestFlattenStringLiterals(t *testing.T) {
	literals := []string{
		"hello",
		"world",
		"",
		"foo",
		"bar",
		"baz",
	}
	expected := []byte("helloworldfoobarbaz")

	result := flattenStringLiterals(literals)

	if !bytes.Equal(result, expected) {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func BenchmarkFlattenStringLiterals(b *testing.B) {
	baseLiterals := []string{
		"some string",
		"another string",
		"yet another string",
		"long string data here to make it worthwile",
		"short",
	}
	var literals []string
	for i := 0; i < 2000; i++ {
		literals = append(literals, baseLiterals...)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = flattenStringLiterals(literals)
	}
}

func TestTruncateToValidUTF8(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Valid ASCII",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "Valid UTF-8",
			input:    "Hello, 世界",
			expected: "Hello, 世界",
		},
		{
			name:     "Invalid at end",
			input:    "Hello, \xFF",
			expected: "Hello, ",
		},
		{
			name:     "Invalid in middle",
			input:    "Hello, \xFF World",
			expected: "Hello, ",
		},
		{
			name:     "Binary start",
			input:    "\xFF\xFE",
			expected: "",
		},
		{
			name:     "Partial multi-byte rune at end",
			input:    string([]byte{0xe4, 0xb8, 0x96, 0xe7, 0x95}), // "世" + first byte of "界"
			expected: "世",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateToValidUTF8(tt.input)
			if result != tt.expected {
				t.Errorf("truncateToValidUTF8(%q) = %q; want %q", tt.input, result, tt.expected)
			}
		})
	}
}
