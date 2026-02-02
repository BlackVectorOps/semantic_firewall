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
