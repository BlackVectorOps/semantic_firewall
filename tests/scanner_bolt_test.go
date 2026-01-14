package semanticfw_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	sfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

func TestNewBoltScanner(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	// Verify database file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}
}

func TestBoltScannerAddAndGetSignature(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	sig := sfw.Signature{
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

func TestBoltScannerAddSignatures(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	sigs := []sfw.Signature{
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

func TestBoltScannerDeleteSignature(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	sig := sfw.Signature{
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

func TestBoltScannerScanTopologyExact(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	// Create a topology
	topo := &sfw.FunctionTopology{
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
	topoHash := sfw.GenerateTopologyHashExported(topo)

	sig := sfw.Signature{
		ID:           "EXACT-001",
		Name:         "Exact_Match",
		Severity:     "CRITICAL",
		TopologyHash: topoHash,
		EntropyScore: 5.0,
		NodeCount:    5,
		LoopDepth:    1,
		IdentifyingFeatures: sfw.IdentifyingFeatures{
			RequiredCalls: []string{"net.Dial", "time.Sleep"},
		},
	}

	scanner.AddSignature(sig)

	// Scan - should get O(1) exact match
	result := scanner.ScanTopologyExact(topo, "test_func")
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

func TestBoltScannerScanTopologyFuzzy(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	opts := sfw.DefaultBoltScannerOptions()
	opts.EntropyTolerance = 1.0 // Wider tolerance for fuzzy matching

	scanner, err := sfw.NewBoltScanner(dbPath, opts)
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()
	scanner.SetThreshold(0.5) // Lower threshold for testing

	// Add signatures with different entropy scores and fuzzy hashes
	// FuzzyHash format: B<log2(blocks)>L<loops>BR<log2(branches)>
	// For BlockCount=5 (log2=2), LoopCount=1, BranchCount=2 (log2=1) -> "B2L1BR1"
	sigs := []sfw.Signature{
		{ID: "LOW-001", Name: "Low_Entropy", TopologyHash: "h1", FuzzyHash: "B2L1BR1", EntropyScore: 3.0, NodeCount: 5, LoopDepth: 1},
		{ID: "MID-001", Name: "Mid_Entropy", TopologyHash: "h2", FuzzyHash: "B2L1BR1", EntropyScore: 5.0, NodeCount: 5, LoopDepth: 1},
		{ID: "HIGH-001", Name: "High_Entropy", TopologyHash: "h3", FuzzyHash: "B3L2BR2", EntropyScore: 7.0, NodeCount: 10, LoopDepth: 2},
	}
	scanner.AddSignatures(sigs)

	// Topology with matching fuzzy hash B2L1BR1 - should match LOW-001 and MID-001
	topo := &sfw.FunctionTopology{
		BlockCount:   5, // log2(5) = 2
		LoopCount:    1,
		BranchCount:  2, // log2(2) = 1
		EntropyScore: 5.2,
	}

	results := scanner.ScanTopology(topo, "fuzzy_func")

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

func TestBoltScannerMigrateFromJSON(t *testing.T) {
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

	// Create new BoltDB scanner
	dbPath := filepath.Join(tmpDir, "migrated.db")
	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
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

func TestBoltScannerExportToJSON(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}

	// Add some signatures
	sigs := []sfw.Signature{
		{ID: "EXPORT-001", Name: "Sig1", TopologyHash: "h1", EntropyScore: 4.0, Severity: "LOW"},
		{ID: "EXPORT-002", Name: "Sig2", TopologyHash: "h2", EntropyScore: 5.0, Severity: "HIGH"},
	}
	scanner.AddSignatures(sigs)
	scanner.Close()

	// Reopen in read mode and export
	scanner, _ = sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	defer scanner.Close()

	jsonPath := filepath.Join(tmpDir, "export.json")
	if err := scanner.ExportToJSON(jsonPath); err != nil {
		t.Fatalf("ExportToJSON() error = %v", err)
	}

	// Verify JSON file was created and is valid
	oldScanner := sfw.NewScanner()
	if err := oldScanner.LoadDatabase(jsonPath); err != nil {
		t.Fatalf("Failed to load exported JSON: %v", err)
	}

	db := oldScanner.GetDatabase()
	if len(db.Signatures) != 2 {
		t.Errorf("Expected 2 signatures in export, got %d", len(db.Signatures))
	}
}

func TestBoltScannerMarkFalsePositive(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	sig := sfw.Signature{
		ID:           "FP-001",
		Name:         "FalsePositive_Test",
		TopologyHash: "fp_hash",
		EntropyScore: 5.0,
		Metadata:     sfw.SignatureMetadata{Author: "test"},
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

func TestBoltScannerRebuildIndexes(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	// Add signatures
	sigs := []sfw.Signature{
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

func TestBoltScannerConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	// Concurrent writes
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sig := sfw.Signature{
				ID:           "CONC-" + string(rune('A'+n)),
				Name:         "Concurrent_Sig",
				TopologyHash: "conc_hash_" + string(rune('A'+n)),
				EntropyScore: float64(n) + 4.0,
			}
			scanner.AddSignature(sig)
		}(i)
	}
	wg.Wait()

	// Verify all were written
	count, err := scanner.CountSignatures()
	if err != nil {
		t.Fatalf("CountSignatures() error = %v", err)
	}
	if count != 10 {
		t.Errorf("Expected 10 signatures after concurrent writes, got %d", count)
	}
}

func TestBoltScannerListSignatureIDs(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	sigs := []sfw.Signature{
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
}

func TestBoltScannerStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	sigs := []sfw.Signature{
		{ID: "STATS-001", Name: "Sig1", TopologyHash: "h1", EntropyScore: 4.0},
		{ID: "STATS-002", Name: "Sig2", TopologyHash: "h2", EntropyScore: 5.0},
	}
	scanner.AddSignatures(sigs)

	stats, err := scanner.Stats()
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}

	if stats.SignatureCount != 2 {
		t.Errorf("Expected SignatureCount 2, got %d", stats.SignatureCount)
	}
	if stats.TopoIndexCount != 2 {
		t.Errorf("Expected TopoIndexCount 2, got %d", stats.TopoIndexCount)
	}
}

func TestFormatEntropyKey(t *testing.T) {
	tests := []struct {
		entropy  float64
		id       string
		expected string
	}{
		{5.1234, "ID-001", "005.1234:ID-001"},
		{0.0, "ZERO", "000.0000:ZERO"},
		{10.5, "HIGH", "010.5000:HIGH"},
		{-1.0, "NEG", "000.0000:NEG"},  // Clamped to 0
		{100.0, "MAX", "099.9999:MAX"}, // Clamped to max
	}

	for _, tc := range tests {
		result := sfw.FormatEntropyKeyExported(tc.entropy, tc.id)
		if result != tc.expected {
			t.Errorf("formatEntropyKey(%f, %q) = %q, want %q",
				tc.entropy, tc.id, result, tc.expected)
		}
	}
}

func TestBoltScannerValidation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	scanner, err := sfw.NewBoltScanner(dbPath, sfw.DefaultBoltScannerOptions())
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()

	// Test adding signature without topology hash (should error)
	sig := sfw.Signature{
		ID:           "INVALID-001",
		Name:         "Missing_Hash",
		TopologyHash: "", // Missing!
		EntropyScore: 5.0,
	}

	err = scanner.AddSignature(sig)
	if err == nil {
		t.Error("Expected error when adding signature without TopologyHash")
	}
}

func TestBoltScannerNoDuplicates(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	opts := sfw.DefaultBoltScannerOptions()
	opts.EntropyTolerance = 2.0 // Wide tolerance

	scanner, err := sfw.NewBoltScanner(dbPath, opts)
	if err != nil {
		t.Fatalf("NewBoltScanner() error = %v", err)
	}
	defer scanner.Close()
	scanner.SetThreshold(0.3)

	// Create topology
	topo := &sfw.FunctionTopology{
		ParamCount:     2,
		ReturnCount:    1,
		BlockCount:     5,
		InstrCount:     30,
		LoopCount:      1,
		BranchCount:    2,
		CallSignatures: map[string]int{"net.Dial": 1},
		EntropyScore:   5.0,
	}

	topoHash := sfw.GenerateTopologyHashExported(topo)

	// Add signature with same topology hash AND within entropy range
	// This should only appear once in results
	sig := sfw.Signature{
		ID:           "DEDUP-001",
		Name:         "Dedup_Test",
		TopologyHash: topoHash,
		EntropyScore: 5.0, // Exact entropy match
		NodeCount:    5,
		LoopDepth:    1,
	}
	scanner.AddSignature(sig)

	results := scanner.ScanTopology(topo, "test_func")

	// Count occurrences of DEDUP-001
	count := 0
	for _, r := range results {
		if r.SignatureID == "DEDUP-001" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("Expected signature to appear exactly once, got %d occurrences", count)
	}
}
