package pebbledb_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/detection"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/storage/pebbledb"
)

func TestPebbleScanner_CRUD(t *testing.T) {
	dbPath := t.TempDir()

	s, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner failed: %v", err)
	}
	defer s.Close()

	sig := detection.Signature{
		ID: "SIG-1", Name: "Test", TopologyHash: "HASH", EntropyScore: 5.0,
	}

	if err := s.AddSignature(&sig); err != nil {
		t.Fatalf("AddSignature failed: %v", err)
	}

	got, err := s.GetSignature("SIG-1")
	if err != nil {
		t.Fatalf("GetSignature failed: %v", err)
	}
	if got.Name != "Test" {
		t.Errorf("Mismatch: %v", got)
	}

	stats, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.SignatureCount != 1 {
		t.Errorf("Expected 1 sig, got %d", stats.SignatureCount)
	}
}

func TestPebbleScanner_IDGeneration(t *testing.T) {
	dbPath := t.TempDir()
	s, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner failed: %v", err)
	}
	defer s.Close()

	// Pass a signature with NO ID
	sig := detection.Signature{
		Name: "AutoID", TopologyHash: "HASH2", EntropyScore: 3.0,
	}

	if err := s.AddSignature(&sig); err != nil {
		t.Fatalf("AddSignature failed: %v", err)
	}

	// Check if ID was populated back
	if sig.ID == "" {
		t.Fatal("Signature ID was not populated after AddSignature")
	}

	// Verify we can retrieve it
	got, err := s.GetSignature(sig.ID)
	if err != nil {
		t.Fatalf("Could not get signature with generated ID %s: %v", sig.ID, err)
	}
	if got.Name != "AutoID" {
		t.Errorf("Expected AutoID, got %s", got.Name)
	}
}

func TestPebbleScanner_BatchDuplicateHandling(t *testing.T) {
	dbPath := t.TempDir()
	s, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner failed: %v", err)
	}
	defer s.Close()

	// Initial add
	sigInitial := detection.Signature{ID: "DUP-1", TopologyHash: "TOPO-1", EntropyScore: 5.0}
	if err := s.AddSignature(&sigInitial); err != nil {
		t.Fatal(err)
	}

	// Batch update: Update "DUP-1" to "TOPO-2", then "TOPO-3" in same batch
	sigs := []*detection.Signature{
		{ID: "DUP-1", TopologyHash: "TOPO-2", EntropyScore: 5.0},
		{ID: "DUP-1", TopologyHash: "TOPO-3", EntropyScore: 5.0},
	}

	if err := s.AddSignatures(sigs); err != nil {
		t.Fatal(err)
	}

	// Check final state - expect TOPO-3
	finalSig, err := s.GetSignature("DUP-1")
	if err != nil {
		t.Fatal(err)
	}
	if finalSig.TopologyHash != "TOPO-3" {
		t.Errorf("Expected TOPO-3, got %s", finalSig.TopologyHash)
	}

	// Verify Indexes
	// TOPO-1 should be gone
	// TOPO-2 should NOT exist (ghost index check)
	// TOPO-3 should exist

	// Helper to check index via GetSignatureByTopology
	checkIndex := func(hash string, shouldExist bool) {
		_, err := s.GetSignatureByTopology(hash)
		exists := (err == nil)

		if shouldExist && !exists {
			t.Errorf("Index for %s missing", hash)
		}
		if !shouldExist && exists {
			t.Errorf("Index for %s should not exist (ghost index found)", hash)
		}
	}

	checkIndex("TOPO-1", false)
	checkIndex("TOPO-2", false)
	checkIndex("TOPO-3", true)
}

func TestPebbleScanner_RebuildIndexes_Streaming(t *testing.T) {
	// Tests the streaming logic of RebuildIndexes to ensure it doesn't crash and correctly rebuilds.
	dbPath := t.TempDir()
	s, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner failed: %v", err)
	}
	defer s.Close()

	// Add 1500 signatures to trigger batching logic (batch size is 1000 in Rebuild)
	var sigs []*detection.Signature
	for i := 0; i < 1500; i++ {
		sigs = append(sigs, &detection.Signature{
			ID:           fmt.Sprintf("REBUILD-%d", i),
			TopologyHash: fmt.Sprintf("HASH-%d", i),
			EntropyScore: 5.0,
		})
	}
	if err := s.AddSignatures(sigs); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if err := s.RebuildIndexes(); err != nil {
		t.Fatalf("RebuildIndexes failed: %v", err)
	}

	// Verify all exist
	stats, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.SignatureCount != 1500 {
		t.Errorf("Signature count mismatch. Want 1500, got %d", stats.SignatureCount)
	}
	if stats.TopoIndexCount != 1500 {
		t.Errorf("Topo Index count mismatch. Want 1500, got %d", stats.TopoIndexCount)
	}

	// Verify query
	sig, err := s.GetSignatureByTopology("HASH-1499")
	if err != nil {
		t.Errorf("Failed to retrieve signature via topology after rebuild: %v", err)
	}
	if sig == nil || sig.ID != "REBUILD-1499" {
		t.Errorf("Wrong signature returned: %v", sig)
	}
}

func TestPebbleScanner_MetadataPersistence(t *testing.T) {
	// Tests the fix for Metadata Reset Bug.
	dbPath := t.TempDir()
	s, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner failed: %v", err)
	}

	// First initialization
	if err := s.InitializeMetadata("1.0", "Desc"); err != nil {
		t.Fatal(err)
	}

	meta1, err := s.GetAllMetadata()
	if err != nil {
		t.Fatal(err)
	}
	created1 := meta1.CreatedAt

	// Sleep to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Close and Reopen to simulate restart
	s.Close()
	s2, err := pebbledb.NewPebbleScanner(dbPath, pebbledb.DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	// Second initialization (Startup)
	if err := s2.InitializeMetadata("1.0", "Desc"); err != nil {
		t.Fatal(err)
	}

	meta2, err := s2.GetAllMetadata()
	if err != nil {
		t.Fatal(err)
	}

	// Verify CreatedAt was preserved
	if !meta2.CreatedAt.Equal(created1) {
		t.Errorf("CreatedAt was reset! Original: %v, New: %v", created1, meta2.CreatedAt)
	}

	// Verify LastUpdatedAt changed (should be > created1)
	if !meta2.LastUpdatedAt.After(created1) {
		t.Errorf("LastUpdatedAt should be updated. Got %v", meta2.LastUpdatedAt)
	}
}
