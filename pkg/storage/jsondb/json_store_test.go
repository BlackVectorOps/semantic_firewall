package jsondb

import (
	"fmt"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
)

func TestGetSignature(t *testing.T) {
	scanner := NewScanner()

	// 1. Add signatures
	sigs := []*detection.Signature{
		{ID: "S1", Name: "Sig 1"},
		{ID: "S2", Name: "Sig 2"},
		{ID: "S3", Name: "Sig 3"},
	}

	for _, sig := range sigs {
		if err := scanner.AddSignature(sig); err != nil {
			t.Fatalf("failed to add signature: %v", err)
		}
	}

	// 2. Retrieve existing signatures
	for _, expected := range sigs {
		got, err := scanner.GetSignature(expected.ID)
		if err != nil {
			t.Errorf("GetSignature(%q) failed: %v", expected.ID, err)
			continue
		}
		if got.ID != expected.ID {
			t.Errorf("GetSignature(%q) returned ID %q", expected.ID, got.ID)
		}
		if got.Name != expected.Name {
			t.Errorf("GetSignature(%q) returned Name %q", expected.Name, got.Name)
		}
	}

	// 3. Retrieve non-existing signature
	if _, err := scanner.GetSignature("NON-EXISTENT"); err == nil {
		t.Error("GetSignature(NON-EXISTENT) should have returned error")
	}
}

func BenchmarkGetSignature(b *testing.B) {
	scanner := NewScanner()
	count := 10000

	// Pre-populate with signatures
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("SIG-%d", i)
		sig := &detection.Signature{
			ID:   id,
			Name: fmt.Sprintf("Signature %d", i),
		}
		if err := scanner.AddSignature(sig); err != nil {
			b.Fatalf("failed to add signature: %v", err)
		}
	}

	targetID := fmt.Sprintf("SIG-%d", count-1) // Last one (worst case for linear scan)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.GetSignature(targetID)
		if err != nil {
			b.Fatalf("failed to get signature: %v", err)
		}
	}
}
