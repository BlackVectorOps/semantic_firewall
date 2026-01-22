package semanticfw

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestNewPebbleScanner(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Verify database directory was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database directory was not created")
	}
}

func TestPebbleScannerAddAndGetSignature(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	sig := Signature{
		ID:           "TEST-001",
		Name:         "Test_Beacon",
		Description:  "A test signature",
		Severity:     "HIGH",
		Category:     "backdoor",
		TopologyHash: "abc123def456",
		EntropyScore: 5.5,
		NodeCount:    10,
		LoopDepth:    2,
	}

	// Add signature
	if err := scanner.AddSignature(sig); err != nil {
		t.Fatalf("AddSignature() error = %v", err)
	}

	// Retrieve by ID
	retrieved, err := scanner.GetSignature("TEST-001")
	if err != nil {
		t.Fatalf("GetSignature() error = %v", err)
	}

	if retrieved.Name != sig.Name {
		t.Errorf("Expected name %q, got %q", sig.Name, retrieved.Name)
	}
	if retrieved.EntropyScore != sig.EntropyScore {
		t.Errorf("Expected entropy %f, got %f", sig.EntropyScore, retrieved.EntropyScore)
	}

	// Retrieve by topology hash
	byTopo, err := scanner.GetSignatureByTopology("abc123def456")
	if err != nil {
		t.Fatalf("GetSignatureByTopology() error = %v", err)
	}
	if byTopo.ID != sig.ID {
		t.Errorf("Expected ID %q, got %q", sig.ID, byTopo.ID)
	}
}

func TestPebbleScannerAddSignatures(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	sigs := []Signature{
		{ID: "BULK-001", Name: "Sig1", TopologyHash: "hash1", EntropyScore: 4.0},
		{ID: "BULK-002", Name: "Sig2", TopologyHash: "hash2", EntropyScore: 5.0},
		{ID: "BULK-003", Name: "Sig3", TopologyHash: "hash3", EntropyScore: 6.0},
	}

	if err := scanner.AddSignatures(sigs); err != nil {
		t.Fatalf("AddSignatures() error = %v", err)
	}

	count, err := scanner.CountSignatures()
	if err != nil {
		t.Fatalf("CountSignatures() error = %v", err)
	}
	if count != 3 {
		t.Errorf("Expected 3 signatures, got %d", count)
	}
}

func TestPebbleScannerDeleteSignature(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	sig := Signature{
		ID:           "DELETE-001",
		Name:         "ToDelete",
		TopologyHash: "deletehash",
		EntropyScore: 5.0,
	}

	scanner.AddSignature(sig)

	// Delete it
	if err := scanner.DeleteSignature("DELETE-001"); err != nil {
		t.Fatalf("DeleteSignature() error = %v", err)
	}

	// Verify it's gone
	_, err = scanner.GetSignature("DELETE-001")
	if err == nil {
		t.Error("Expected error when getting deleted signature")
	}

	// Verify index is also cleared
	_, err = scanner.GetSignatureByTopology("deletehash")
	if err == nil {
		t.Error("Expected error when getting deleted signature by topology")
	}
}

func TestPebbleScannerScanTopologyExact(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Create a topology
	topo := &FunctionTopology{
		ParamCount:     2,
		ReturnCount:    1,
		BlockCount:     5,
		InstrCount:     30,
		LoopCount:      1,
		BranchCount:    2,
		CallSignatures: map[string]int{"net.Dial": 1, "time.Sleep": 1},
		HasDefer:       true,
		EntropyScore:   5.2,
	}

	// Generate hash and create matching signature
	topoHash := generateTopologyHash(topo)

	sig := Signature{
		ID:           "EXACT-001",
		Name:         "Exact_Match",
		Severity:     "CRITICAL",
		TopologyHash: topoHash,
		EntropyScore: 5.0,
		NodeCount:    5,
		LoopDepth:    1,
		IdentifyingFeatures: IdentifyingFeatures{
			RequiredCalls: []string{"net.Dial", "time.Sleep"},
		},
	}

	scanner.AddSignature(sig)

	// Scan - should get O(1) exact match
	result, err := scanner.ScanTopologyExact(topo, "test_func")
	if err != nil {
		t.Fatalf("ScanTopologyExact failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected exact match result, got nil")
	}

	if result.SignatureID != "EXACT-001" {
		t.Errorf("Expected signature ID 'EXACT-001', got %q", result.SignatureID)
	}

	if !result.MatchDetails.TopologyMatch {
		t.Error("Expected TopologyMatch to be true")
	}

	if result.MatchDetails.TopologySimilarity != 1.0 {
		t.Errorf("Expected TopologySimilarity 1.0, got %f", result.MatchDetails.TopologySimilarity)
	}
}

func TestPebbleScannerScanTopologyFuzzy(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	opts := DefaultPebbleScannerOptions()
	opts.EntropyTolerance = 1.0 // Wider tolerance for fuzzy matching

	scanner, err := NewPebbleScanner(dbPath, opts)
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()
	scanner.SetThreshold(0.5) // Lower threshold for testing

	// Define topology first to generate the correct fuzzy hash
	topo := &FunctionTopology{
		BlockCount:   5, // log2(5) = 2
		LoopCount:    1,
		BranchCount:  2, // log2(2) = 1
		EntropyScore: 5.2,
	}
	// FIX: Generate the hash dynamically so the test is robust against algorithm changes
	targetFuzzyHash := GenerateFuzzyHash(topo)

	// Add signatures with different entropy scores and fuzzy hashes
	sigs := []Signature{
		{ID: "LOW-001", Name: "Low_Entropy", TopologyHash: "h1", FuzzyHash: targetFuzzyHash, EntropyScore: 3.0, NodeCount: 5, LoopDepth: 1},
		{ID: "MID-001", Name: "Mid_Entropy", TopologyHash: "h2", FuzzyHash: targetFuzzyHash, EntropyScore: 5.0, NodeCount: 5, LoopDepth: 1},
		{ID: "HIGH-001", Name: "High_Entropy", TopologyHash: "h3", FuzzyHash: "B3L2BR2", EntropyScore: 7.0, NodeCount: 10, LoopDepth: 2},
	}
	scanner.AddSignatures(sigs)

	results, err := scanner.ScanTopology(topo, "fuzzy_func")
	if err != nil {
		t.Fatalf("ScanTopology failed: %v", err)
	}

	// Should find at least the mid-entropy signature
	found := false
	for _, r := range results {
		if r.SignatureID == "MID-001" {
			found = true
			if !r.MatchDetails.EntropyMatch {
				t.Error("Expected EntropyMatch to be true for MID-001")
			}
		}
	}

	if !found {
		t.Error("Expected to find MID-001 in fuzzy scan results")
	}
}

func TestPebbleScannerMigrateFromJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create legacy JSON database
	jsonPath := filepath.Join(tmpDir, "legacy.json")
	testJSON := `{
		"version": "1.0",
		"description": "Legacy database",
		"signatures": [
			{
				"id": "LEGACY-001",
				"name": "Legacy_Sig_1",
				"topology_hash": "legacy_hash_1",
				"entropy_score": 4.5,
				"severity": "HIGH"
			},
			{
				"id": "LEGACY-002", 
				"name": "Legacy_Sig_2",
				"topology_hash": "legacy_hash_2",
				"entropy_score": 5.5,
				"severity": "CRITICAL"
			}
		]
	}`
	if err := os.WriteFile(jsonPath, []byte(testJSON), 0644); err != nil {
		t.Fatalf("Failed to write test JSON: %v", err)
	}

	// Create new Pebble scanner
	dbPath := filepath.Join(tmpDir, "migrated_pebble")
	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Migrate
	count, err := scanner.MigrateFromJSON(jsonPath)
	if err != nil {
		t.Fatalf("MigrateFromJSON() error = %v", err)
	}

	if count != 2 {
		t.Errorf("Expected 2 migrated signatures, got %d", count)
	}

	// Verify signatures are accessible
	sig, err := scanner.GetSignature("LEGACY-001")
	if err != nil {
		t.Fatalf("GetSignature() error = %v", err)
	}
	if sig.Name != "Legacy_Sig_1" {
		t.Errorf("Expected name 'Legacy_Sig_1', got %q", sig.Name)
	}

	// Verify indexes work
	sig2, err := scanner.GetSignatureByTopology("legacy_hash_2")
	if err != nil {
		t.Fatalf("GetSignatureByTopology() error = %v", err)
	}
	if sig2.ID != "LEGACY-002" {
		t.Errorf("Expected ID 'LEGACY-002', got %q", sig2.ID)
	}
}

func TestPebbleScannerExportToJSON(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}

	// Add some signatures
	sigs := []Signature{
		{ID: "EXPORT-001", Name: "Sig1", TopologyHash: "h1", EntropyScore: 4.0, Severity: "LOW"},
		{ID: "EXPORT-002", Name: "Sig2", TopologyHash: "h2", EntropyScore: 5.0, Severity: "HIGH"},
	}
	scanner.AddSignatures(sigs)
	scanner.Close()

	// Reopen and export
	scanner, _ = NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	defer scanner.Close()

	jsonPath := filepath.Join(tmpDir, "export.json")
	if err := scanner.ExportToJSON(jsonPath); err != nil {
		t.Fatalf("ExportToJSON() error = %v", err)
	}

	// Verify JSON file was created and is valid
	oldScanner := NewScanner()
	if err := oldScanner.LoadDatabase(jsonPath); err != nil {
		t.Fatalf("Failed to load exported JSON: %v", err)
	}

	db := oldScanner.GetDatabase()
	if len(db.Signatures) != 2 {
		t.Errorf("Expected 2 signatures in export, got %d", len(db.Signatures))
	}
}

func TestPebbleScannerMarkFalsePositive(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	sig := Signature{
		ID:           "FP-001",
		Name:         "FalsePositive_Test",
		TopologyHash: "fp_hash",
		EntropyScore: 5.0,
		Metadata:     SignatureMetadata{Author: "test"},
	}
	scanner.AddSignature(sig)

	// Mark as false positive
	if err := scanner.MarkFalsePositive("FP-001", "Detected benign code in test suite"); err != nil {
		t.Fatalf("MarkFalsePositive() error = %v", err)
	}

	// Verify note was added
	updated, _ := scanner.GetSignature("FP-001")
	if len(updated.Metadata.References) == 0 {
		t.Error("Expected false positive note to be added")
	}

	found := false
	for _, ref := range updated.Metadata.References {
		if len(ref) > 3 && ref[:3] == "FP:" {
			found = true
		}
	}
	if !found {
		t.Error("Expected to find FP: prefixed note in references")
	}
}

func TestPebbleScannerRebuildIndexes(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Add signatures
	sigs := []Signature{
		{ID: "REBUILD-001", Name: "Sig1", TopologyHash: "rebuild_h1", EntropyScore: 4.0},
		{ID: "REBUILD-002", Name: "Sig2", TopologyHash: "rebuild_h2", EntropyScore: 5.0},
	}
	scanner.AddSignatures(sigs)

	// Rebuild indexes
	if err := scanner.RebuildIndexes(); err != nil {
		t.Fatalf("RebuildIndexes() error = %v", err)
	}

	// Verify indexes still work
	sig, err := scanner.GetSignatureByTopology("rebuild_h1")
	if err != nil {
		t.Fatalf("GetSignatureByTopology() error after rebuild = %v", err)
	}
	if sig.ID != "REBUILD-001" {
		t.Errorf("Expected ID 'REBUILD-001', got %q", sig.ID)
	}
}

func TestPebbleScannerConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Concurrent writes - Pebble handles this much better than BoltDB
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sig := Signature{
				ID:           "CONC-" + string(rune('A'+n)),
				Name:         "Concurrent_Sig",
				TopologyHash: "conc_hash_" + string(rune('A'+n)),
				EntropyScore: float64(n) + 4.0,
			}
			scanner.AddSignature(sig)
		}(i)
	}
	wg.Wait()

	count, _ := scanner.CountSignatures()
	if count != 10 {
		t.Errorf("Expected 10 signatures after concurrent writes, got %d", count)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := "CONC-" + string(rune('A'+n))
			_, err := scanner.GetSignature(id)
			if err != nil {
				t.Errorf("Concurrent read failed for %s: %v", id, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestPebbleScannerScanByEntropyRange(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Add signatures with different entropy scores
	sigs := []Signature{
		{ID: "ENT-001", Name: "Low", TopologyHash: "h1", EntropyScore: 2.0},
		{ID: "ENT-002", Name: "Mid1", TopologyHash: "h2", EntropyScore: 4.5},
		{ID: "ENT-003", Name: "Mid2", TopologyHash: "h3", EntropyScore: 5.5},
		{ID: "ENT-004", Name: "High", TopologyHash: "h4", EntropyScore: 8.0},
	}
	scanner.AddSignatures(sigs)

	// Search for entropy range 4.0 to 6.0
	results, err := scanner.ScanByEntropyRange(4.0, 6.0)
	if err != nil {
		t.Fatalf("ScanByEntropyRange() error = %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results in entropy range 4-6, got %d", len(results))
	}

	// Verify correct signatures were found
	ids := make(map[string]bool)
	for _, sig := range results {
		ids[sig.ID] = true
	}
	if !ids["ENT-002"] || !ids["ENT-003"] {
		t.Error("Expected ENT-002 and ENT-003 in entropy range results")
	}
}

func TestPebbleScannerScanBatch(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Create signatures with specific topology hashes
	topo1 := &FunctionTopology{
		BlockCount:   5,
		LoopCount:    1,
		BranchCount:  2,
		EntropyScore: 5.0,
	}
	topo2 := &FunctionTopology{
		BlockCount:   8,
		LoopCount:    2,
		BranchCount:  4,
		EntropyScore: 6.0,
	}

	hash1 := generateTopologyHash(topo1)
	hash2 := generateTopologyHash(topo2)

	sigs := []Signature{
		{ID: "BATCH-001", Name: "Sig1", TopologyHash: hash1, EntropyScore: 5.0},
		{ID: "BATCH-002", Name: "Sig2", TopologyHash: hash2, EntropyScore: 6.0},
	}
	scanner.AddSignatures(sigs)

	// Batch scan
	topos := map[string]*FunctionTopology{
		"func1": topo1,
		"func2": topo2,
	}

	results := scanner.ScanBatch(topos)

	if len(results) != 2 {
		t.Errorf("Expected 2 functions with results, got %d", len(results))
	}

	if _, ok := results["func1"]; !ok {
		t.Error("Expected results for func1")
	}
	if _, ok := results["func2"]; !ok {
		t.Error("Expected results for func2")
	}
}

func TestPebbleScannerStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Add signatures with fuzzy hashes
	sigs := []Signature{
		{ID: "STATS-001", Name: "Sig1", TopologyHash: "h1", FuzzyHash: "B2L1BR1", EntropyScore: 4.0},
		{ID: "STATS-002", Name: "Sig2", TopologyHash: "h2", FuzzyHash: "B3L2BR2", EntropyScore: 5.0},
		{ID: "STATS-003", Name: "Sig3", TopologyHash: "h3", EntropyScore: 6.0}, // No fuzzy hash
	}
	scanner.AddSignatures(sigs)

	stats, err := scanner.Stats()
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}

	if stats.SignatureCount != 3 {
		t.Errorf("Expected 3 signatures, got %d", stats.SignatureCount)
	}
	if stats.TopoIndexCount != 3 {
		t.Errorf("Expected 3 topology index entries, got %d", stats.TopoIndexCount)
	}
	if stats.FuzzyIndexCount != 2 {
		t.Errorf("Expected 2 fuzzy index entries, got %d", stats.FuzzyIndexCount)
	}
	if stats.EntropyIndexCount != 3 {
		t.Errorf("Expected 3 entropy index entries, got %d", stats.EntropyIndexCount)
	}
}

func TestPebbleScannerListSignatureIDs(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	sigs := []Signature{
		{ID: "LIST-001", Name: "Sig1", TopologyHash: "h1", EntropyScore: 4.0},
		{ID: "LIST-002", Name: "Sig2", TopologyHash: "h2", EntropyScore: 5.0},
		{ID: "LIST-003", Name: "Sig3", TopologyHash: "h3", EntropyScore: 6.0},
	}
	scanner.AddSignatures(sigs)

	ids, err := scanner.ListSignatureIDs()
	if err != nil {
		t.Fatalf("ListSignatureIDs() error = %v", err)
	}

	if len(ids) != 3 {
		t.Errorf("Expected 3 IDs, got %d", len(ids))
	}

	idMap := make(map[string]bool)
	for _, id := range ids {
		idMap[id] = true
	}

	for _, sig := range sigs {
		if !idMap[sig.ID] {
			t.Errorf("Missing ID %s in list", sig.ID)
		}
	}
}

func TestPebbleScannerReadOnlyMode(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	// First create and populate the database
	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}

	sig := Signature{
		ID:           "RO-001",
		Name:         "ReadOnly_Test",
		TopologyHash: "ro_hash",
		EntropyScore: 5.0,
	}
	scanner.AddSignature(sig)
	scanner.Close()

	// Reopen in read-only mode
	opts := DefaultPebbleScannerOptions()
	opts.ReadOnly = true

	roScanner, err := NewPebbleScanner(dbPath, opts)
	if err != nil {
		t.Fatalf("NewPebbleScanner(ReadOnly) error = %v", err)
	}
	defer roScanner.Close()

	// Reading should work
	retrieved, err := roScanner.GetSignature("RO-001")
	if err != nil {
		t.Fatalf("GetSignature() in ReadOnly mode error = %v", err)
	}
	if retrieved.Name != "ReadOnly_Test" {
		t.Errorf("Expected name 'ReadOnly_Test', got %q", retrieved.Name)
	}
}

func TestPebbleScannerReadOnlyNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "nonexistent_pebble")

	opts := DefaultPebbleScannerOptions()
	opts.ReadOnly = true

	// Should fail because database doesn't exist
	_, err := NewPebbleScanner(dbPath, opts)
	if err == nil {
		t.Error("Expected error when opening non-existent database in ReadOnly mode")
	}
}

func TestPebbleScannerSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Add initial signature
	topo := &FunctionTopology{
		BlockCount:   5,
		LoopCount:    1,
		EntropyScore: 5.0,
	}
	hash := generateTopologyHash(topo)

	sig := Signature{
		ID:           "SNAP-001",
		Name:         "Snapshot_Test",
		TopologyHash: hash,
		EntropyScore: 5.0,
	}
	scanner.AddSignature(sig)

	// Take snapshot
	snap := scanner.GetSnapshot()
	defer snap.Close()

	// Add another signature after snapshot
	sig2 := Signature{
		ID:           "SNAP-002",
		Name:         "After_Snapshot",
		TopologyHash: "different_hash",
		EntropyScore: 6.0,
	}
	scanner.AddSignature(sig2)

	// Scan with snapshot - should only see SNAP-001
	results, err := scanner.ScanTopologyWithSnapshot(snap, topo, "test_func")
	if err != nil {
		t.Fatalf("ScanTopologyWithSnapshot failed: %v", err)
	}

	for _, r := range results {
		if r.SignatureID == "SNAP-002" {
			t.Error("Snapshot scan should not see signatures added after snapshot")
		}
	}
}

func TestPebbleScannerCompact(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Add and delete some signatures to create fragmentation
	for i := 0; i < 100; i++ {
		sig := Signature{
			ID:           "COMPACT-" + string(rune(i)),
			Name:         "Compact_Test",
			TopologyHash: "compact_hash_" + string(rune(i)),
			EntropyScore: float64(i),
		}
		scanner.AddSignature(sig)
	}

	for i := 0; i < 50; i++ {
		scanner.DeleteSignature("COMPACT-" + string(rune(i)))
	}

	// Compact should not error
	if err := scanner.Compact(); err != nil {
		t.Fatalf("Compact() error = %v", err)
	}

	// Verify remaining signatures are intact
	count, _ := scanner.CountSignatures()
	if count != 50 {
		t.Errorf("Expected 50 signatures after compact, got %d", count)
	}
}

func TestPebbleScannerCheckpoint(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	sig := Signature{
		ID:           "CKPT-001",
		Name:         "Checkpoint_Test",
		TopologyHash: "ckpt_hash",
		EntropyScore: 5.0,
	}
	scanner.AddSignature(sig)

	// Checkpoint should flush all data to disk
	if err := scanner.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint() error = %v", err)
	}

	// Data should be durable
	retrieved, err := scanner.GetSignature("CKPT-001")
	if err != nil {
		t.Fatalf("GetSignature() after Checkpoint error = %v", err)
	}
	if retrieved.Name != "Checkpoint_Test" {
		t.Error("Data not persisted after checkpoint")
	}
}

// Benchmark: Compare Pebble vs Bolt performance
func BenchmarkPebbleScannerAddSignature(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench_pebble")

	scanner, _ := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	defer scanner.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig := Signature{
			ID:           "BENCH-" + string(rune(i%1000000)),
			Name:         "Benchmark_Sig",
			TopologyHash: "bench_hash_" + string(rune(i%1000000)),
			EntropyScore: float64(i % 100),
		}
		scanner.AddSignature(sig)
	}
}

func BenchmarkPebbleScannerScanTopologyExact(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench_pebble")

	scanner, _ := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	defer scanner.Close()

	// Pre-populate with signatures
	topo := &FunctionTopology{
		BlockCount:   5,
		LoopCount:    1,
		BranchCount:  2,
		EntropyScore: 5.0,
	}
	hash := generateTopologyHash(topo)

	for i := 0; i < 1000; i++ {
		sig := Signature{
			ID:           "BENCH-" + string(rune(i)),
			Name:         "Benchmark_Sig",
			TopologyHash: hash,
			EntropyScore: 5.0,
		}
		scanner.AddSignature(sig)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.ScanTopologyExact(topo, "bench_func")
	}
}

// -- METADATA TESTS --

func TestPebbleScannerSetGetMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Set metadata
	if err := scanner.SetMetadata("version", "1.0.0"); err != nil {
		t.Fatalf("SetMetadata() error = %v", err)
	}
	if err := scanner.SetMetadata("author", "semantic_firewall"); err != nil {
		t.Fatalf("SetMetadata() error = %v", err)
	}

	// Get metadata
	version, err := scanner.GetMetadata("version")
	if err != nil {
		t.Fatalf("GetMetadata() error = %v", err)
	}
	if version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got %q", version)
	}

	author, err := scanner.GetMetadata("author")
	if err != nil {
		t.Fatalf("GetMetadata() error = %v", err)
	}
	if author != "semantic_firewall" {
		t.Errorf("Expected author 'semantic_firewall', got %q", author)
	}

	// Get non-existent key
	_, err = scanner.GetMetadata("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent metadata key")
	}
}

func TestPebbleScannerDeleteMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Set and delete
	scanner.SetMetadata("temp_key", "temp_value")

	if err := scanner.DeleteMetadata("temp_key"); err != nil {
		t.Fatalf("DeleteMetadata() error = %v", err)
	}

	// Should be gone
	_, err = scanner.GetMetadata("temp_key")
	if err == nil {
		t.Error("Expected error after deleting metadata key")
	}
}

func TestPebbleScannerInitializeMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Initialize
	if err := scanner.InitializeMetadata("2.0.0", "Test database"); err != nil {
		t.Fatalf("InitializeMetadata() error = %v", err)
	}

	// Verify
	meta, err := scanner.GetAllMetadata()
	if err != nil {
		t.Fatalf("GetAllMetadata() error = %v", err)
	}

	if meta.Version != "2.0.0" {
		t.Errorf("Expected version '2.0.0', got %q", meta.Version)
	}
	if meta.Description != "Test database" {
		t.Errorf("Expected description 'Test database', got %q", meta.Description)
	}
	if meta.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if meta.LastUpdatedAt.IsZero() {
		t.Error("Expected LastUpdatedAt to be set")
	}
}

func TestPebbleScannerGetAllMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Add some signatures to verify count
	sigs := []Signature{
		{ID: "META-001", Name: "Sig1", TopologyHash: "h1", EntropyScore: 4.0},
		{ID: "META-002", Name: "Sig2", TopologyHash: "h2", EntropyScore: 5.0},
	}
	scanner.AddSignatures(sigs)

	// Set metadata with custom fields
	scanner.SetMetadata("version", "1.2.3")
	scanner.SetMetadata("source_hash", "abc123")
	scanner.SetMetadata("custom_field", "custom_value")

	meta, err := scanner.GetAllMetadata()
	if err != nil {
		t.Fatalf("GetAllMetadata() error = %v", err)
	}

	if meta.Version != "1.2.3" {
		t.Errorf("Expected version '1.2.3', got %q", meta.Version)
	}
	if meta.SourceHash != "abc123" {
		t.Errorf("Expected source_hash 'abc123', got %q", meta.SourceHash)
	}
	if meta.SignatureCount != 2 {
		t.Errorf("Expected SignatureCount 2, got %d", meta.SignatureCount)
	}
	if meta.Custom["custom_field"] != "custom_value" {
		t.Errorf("Expected custom_field 'custom_value', got %q", meta.Custom["custom_field"])
	}
}

func TestPebbleScannerSetAllMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Set all metadata at once
	meta := &DatabaseMetadata{
		Version:     "3.0.0",
		Description: "Production database",
		SourceHash:  "deadbeef",
		Custom: map[string]string{
			"maintainer":  "security-team",
			"environment": "prod",
		},
	}

	if err := scanner.SetAllMetadata(meta); err != nil {
		t.Fatalf("SetAllMetadata() error = %v", err)
	}

	// Verify individual reads
	version, _ := scanner.GetMetadata("version")
	if version != "3.0.0" {
		t.Errorf("Expected version '3.0.0', got %q", version)
	}

	maintainer, _ := scanner.GetMetadata("maintainer")
	if maintainer != "security-team" {
		t.Errorf("Expected maintainer 'security-team', got %q", maintainer)
	}
}

func TestPebbleScannerTouchLastUpdated(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_pebble")

	scanner, err := NewPebbleScanner(dbPath, DefaultPebbleScannerOptions())
	if err != nil {
		t.Fatalf("NewPebbleScanner() error = %v", err)
	}
	defer scanner.Close()

	// Touch
	if err := scanner.TouchLastUpdated(); err != nil {
		t.Fatalf("TouchLastUpdated() error = %v", err)
	}

	// Verify timestamp exists and is recent
	meta, _ := scanner.GetAllMetadata()
	if meta.LastUpdatedAt.IsZero() {
		t.Error("Expected LastUpdatedAt to be set after TouchLastUpdated")
	}
}
