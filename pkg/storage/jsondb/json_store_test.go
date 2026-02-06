package jsondb

import (
	"fmt"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
)

func TestAddSignatures(t *testing.T) {
	s := NewScanner()
	sigs := []detection.Signature{
		{Name: "Sig1"},
		{Name: "Sig2"},
	}
	if err := s.AddSignatures(sigs); err != nil {
		t.Fatalf("AddSignatures failed: %v", err)
	}

	if len(s.db.Signatures) != 2 {
		t.Errorf("Expected 2 signatures, got %d", len(s.db.Signatures))
	}
	if s.db.Signatures[0].Name != "Sig1" {
		t.Errorf("Expected Sig1, got %s", s.db.Signatures[0].Name)
	}
    // Verify IDs were generated
    if s.db.Signatures[0].ID == "" {
        t.Error("ID should have been generated for Sig1")
    }
}

const count = 10000

func BenchmarkAddSignatureLoop(b *testing.B) {
	sigs := make([]detection.Signature, count)
	for i := 0; i < count; i++ {
		sigs[i] = detection.Signature{
			ID:   fmt.Sprintf("SIG-%d", i),
			Name: fmt.Sprintf("Signature %d", i),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner()
		s.db.Signatures = make([]detection.Signature, 0, count)

		for j := 0; j < count; j++ {
			_ = s.AddSignature(&sigs[j])
		}
	}
}

func BenchmarkAddSignaturesBatch(b *testing.B) {
	sigs := make([]detection.Signature, count)
	for i := 0; i < count; i++ {
		sigs[i] = detection.Signature{
			ID:   fmt.Sprintf("SIG-%d", i),
			Name: fmt.Sprintf("Signature %d", i),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner()
		s.db.Signatures = make([]detection.Signature, 0, count)
		_ = s.AddSignatures(sigs)
	}
}
