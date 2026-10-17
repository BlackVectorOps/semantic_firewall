package jsondb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/detection"
)

func TestLoadDatabase_PermissionDeniedDoesNotPanic(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses unix permission checks")
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sigs.json")
	if err := os.WriteFile(dbPath, []byte(`{"signatures":[]}`), 0o600); err != nil {
		t.Fatalf("write db: %v", err)
	}
	// Strip read+execute from the containing directory so stat fails with EACCES
	// rather than ENOENT. This is the case the old code crashed on.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	s := NewScanner()
	err := s.LoadDatabase(dbPath)
	if err == nil {
		t.Fatal("expected LoadDatabase to error on permission denied, got nil")
	}
	if strings.Contains(err.Error(), "does not exist") {
		t.Errorf("permission error misreported as missing file: %v", err)
	}
}

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

func TestAddSignatures_UpdatesSigMap(t *testing.T) {
	s := NewScanner()
	sigs := []detection.Signature{
		{ID: "SFW-BATCH-1", Name: "Sig1"},
		{ID: "SFW-BATCH-2", Name: "Sig2"},
	}
	if err := s.AddSignatures(sigs); err != nil {
		t.Fatalf("AddSignatures failed: %v", err)
	}

	// GetSignature relies on sigMap; if the batch path skipped indexing it
	// returns "not found" even though the signature is present in the slice.
	for _, want := range sigs {
		got, err := s.GetSignature(want.ID)
		if err != nil {
			t.Errorf("GetSignature(%q) after batch insert: %v", want.ID, err)
			continue
		}
		if got.Name != want.Name {
			t.Errorf("GetSignature(%q).Name = %q, want %q", want.ID, got.Name, want.Name)
		}
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

// SaveDatabase applies the same system-directory guard as PebbleDB writes,
// including through a symlinked parent of a file that does not exist yet.
func TestSaveDatabase_RefusesSystemDir(t *testing.T) {
	if _, err := os.Stat("/etc"); err != nil {
		t.Skip("/etc not present")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	s := NewScanner()
	for _, p := range []string{"/etc/sfw-test.json", filepath.Join(link, "sfw-test.json")} {
		if err := s.SaveDatabase(p); err == nil || !strings.Contains(err.Error(), "security violation") {
			t.Errorf("SaveDatabase(%q) = %v; want a security violation", p, err)
		}
	}
	ok := filepath.Join(t.TempDir(), "sigs.json")
	if err := s.SaveDatabase(ok); err != nil {
		t.Errorf("SaveDatabase(%q) = %v; want nil", ok, err)
	}
}

// AddSignature gives a signature without an ID one and writes it back to
// the caller's struct, as the PebbleDB store does.
func TestAddSignature_WritesBackID(t *testing.T) {
	s := NewScanner()
	sig := detection.Signature{Name: "S"}
	if err := s.AddSignature(&sig); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sig.ID, "SFW-AUTO-") {
		t.Fatalf("ID = %q; want a generated SFW-AUTO- ID", sig.ID)
	}
	if got, err := s.GetSignature(sig.ID); err != nil || got.Name != "S" {
		t.Errorf("GetSignature(%q) = %+v, %v", sig.ID, got, err)
	}
}
