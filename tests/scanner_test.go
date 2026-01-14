package semanticfw_test

import (
	"os"
	"path/filepath"
	"testing"

	sfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

func TestScannerLoadDatabase(t *testing.T) {
	// Create a temporary signature file
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_signatures.json")

	testDB := `{
		"version": "1.0",
		"description": "Test database",
		"signatures": [
			{
				"id": "TEST-001",
				"name": "Test_Signature",
				"severity": "HIGH",
				"category": "test",
				"topology_hash": "abc123",
				"entropy_score": 5.5,
				"entropy_tolerance": 0.5,
				"node_count": 10,
				"loop_depth": 1
			}
		]
	}`

	if err := os.WriteFile(dbPath, []byte(testDB), 0644); err != nil {
		t.Fatalf("Failed to write test database: %v", err)
	}

	scanner := sfw.NewScanner()
	if err := scanner.LoadDatabase(dbPath); err != nil {
		t.Fatalf("LoadDatabase() error = %v", err)
	}

	db := scanner.GetDatabase()
	if db == nil {
		t.Fatal("GetDatabase() returned nil")
	}

	if len(db.Signatures) != 1 {
		t.Errorf("Expected 1 signature, got %d", len(db.Signatures))
	}

	if db.Signatures[0].Name != "Test_Signature" {
		t.Errorf("Expected signature name 'Test_Signature', got '%s'", db.Signatures[0].Name)
	}
}

func TestIndexFunction(t *testing.T) {
	// Create a mock topology
	topo := &sfw.FunctionTopology{
		ParamCount:  2,
		ReturnCount: 1,
		BlockCount:  5,
		InstrCount:  30,
		LoopCount:   1,
		BranchCount: 2,
		CallSignatures: map[string]int{
			"net.Dial":    1,
			"time.Sleep":  1,
			"fmt.Println": 2,
		},
		HasDefer:       true,
		StringLiterals: []string{"\"tcp\"", "\"error\""},
		EntropyScore:   5.2,
	}

	sig := sfw.IndexFunction(topo, "Test_Malware", "A test signature", "CRITICAL", "backdoor")

	if sig.Name != "Test_Malware" {
		t.Errorf("Expected name 'Test_Malware', got '%s'", sig.Name)
	}

	if sig.Severity != "CRITICAL" {
		t.Errorf("Expected severity 'CRITICAL', got '%s'", sig.Severity)
	}

	if sig.TopologyHash == "" {
		t.Error("Expected non-empty topology hash")
	}

	if sig.EntropyScore != 5.2 {
		t.Errorf("Expected entropy score 5.2, got %f", sig.EntropyScore)
	}

	if sig.NodeCount != 5 {
		t.Errorf("Expected node count 5, got %d", sig.NodeCount)
	}

	if sig.LoopDepth != 1 {
		t.Errorf("Expected loop depth 1, got %d", sig.LoopDepth)
	}

	// Should detect reconnect pattern (net.Dial + time.Sleep + loop)
	if sig.IdentifyingFeatures.ControlFlow == nil {
		t.Error("Expected ControlFlow hints to be populated")
	} else if !sig.IdentifyingFeatures.ControlFlow.HasReconnectLogic {
		t.Error("Expected HasReconnectLogic to be true")
	}
}

func TestScanTopology(t *testing.T) {
	scanner := sfw.NewScanner()
	scanner.SetThreshold(0.5) // Lower threshold for testing

	// Create a test signature
	sig := sfw.Signature{
		ID:               "TEST-001",
		Name:             "Beacon_Pattern",
		Severity:         "HIGH",
		TopologyHash:     "will_not_match",
		EntropyScore:     5.0,
		EntropyTolerance: 1.0,
		NodeCount:        5,
		LoopDepth:        1,
		IdentifyingFeatures: sfw.IdentifyingFeatures{
			RequiredCalls: []string{"net.Dial", "time.Sleep"},
		},
	}
	scanner.AddSignature(sig)

	// Create a topology that should match
	topo := &sfw.FunctionTopology{
		BlockCount: 5,
		LoopCount:  1,
		CallSignatures: map[string]int{
			"net.Dial":   1,
			"time.Sleep": 1,
		},
		EntropyScore: 5.2,
	}

	results := scanner.ScanTopology(topo, "suspicious_func")

	if len(results) == 0 {
		t.Error("Expected at least one match result")
		return
	}

	result := results[0]
	if result.SignatureID != "TEST-001" {
		t.Errorf("Expected signature ID 'TEST-001', got '%s'", result.SignatureID)
	}

	if result.MatchedFunction != "suspicious_func" {
		t.Errorf("Expected matched function 'suspicious_func', got '%s'", result.MatchedFunction)
	}

	// Check match details
	if !result.MatchDetails.EntropyMatch {
		t.Error("Expected entropy match to be true")
	}

	if len(result.MatchDetails.CallsMatched) != 2 {
		t.Errorf("Expected 2 calls matched, got %d", len(result.MatchDetails.CallsMatched))
	}
}

func TestGenerateTopologyHash(t *testing.T) {
	topo1 := &sfw.FunctionTopology{
		ParamCount:     2,
		ReturnCount:    1,
		BlockCount:     5,
		InstrCount:     30,
		LoopCount:      1,
		BranchCount:    2,
		CallSignatures: map[string]int{"net.Dial": 1},
		HasDefer:       true,
	}

	topo2 := &sfw.FunctionTopology{
		ParamCount:     2,
		ReturnCount:    1,
		BlockCount:     5,
		InstrCount:     30,
		LoopCount:      1,
		BranchCount:    2,
		CallSignatures: map[string]int{"net.Dial": 1},
		HasDefer:       true,
	}

	// Same topology should produce same hash
	hash1 := sfw.GenerateTopologyHashExported(topo1)
	hash2 := sfw.GenerateTopologyHashExported(topo2)

	if hash1 != hash2 {
		t.Errorf("Same topology produced different hashes: %s != %s", hash1, hash2)
	}

	// Different topology should produce different hash
	topo2.LoopCount = 2
	hash3 := sfw.GenerateTopologyHashExported(topo2)

	if hash1 == hash3 {
		t.Error("Different topology produced same hash")
	}
}

func TestComputeTopologySimilarity(t *testing.T) {
	topo := &sfw.FunctionTopology{
		BlockCount: 10,
		LoopCount:  2,
	}

	// Exact match
	sig1 := sfw.Signature{NodeCount: 10, LoopDepth: 2}
	sim1 := sfw.ComputeTopologySimilarityExported(topo, sig1)
	if sim1 != 1.0 {
		t.Errorf("Expected similarity 1.0 for exact match, got %f", sim1)
	}

	// Partial match
	sig2 := sfw.Signature{NodeCount: 20, LoopDepth: 2}
	sim2 := sfw.ComputeTopologySimilarityExported(topo, sig2)
	if sim2 < 0.5 || sim2 > 1.0 {
		t.Errorf("Expected similarity between 0.5 and 1.0 for partial match, got %f", sim2)
	}
}

func TestMatchCalls(t *testing.T) {
	topo := &sfw.FunctionTopology{
		CallSignatures: map[string]int{
			"net.Dial":    1,
			"time.Sleep":  1,
			"fmt.Println": 2,
		},
	}

	required := []string{"net.Dial", "time.Sleep", "os/exec.Command"}
	score, matched, missing := sfw.MatchCallsExported(topo, required)

	if len(matched) != 2 {
		t.Errorf("Expected 2 matched calls, got %d", len(matched))
	}

	if len(missing) != 1 {
		t.Errorf("Expected 1 missing call, got %d", len(missing))
	}

	expectedScore := 2.0 / 3.0
	if score < expectedScore-0.01 || score > expectedScore+0.01 {
		t.Errorf("Expected score ~%f, got %f", expectedScore, score)
	}
}

func TestAddSignature(t *testing.T) {
	scanner := sfw.NewScanner()

	sig := sfw.Signature{
		Name:     "New_Signature",
		Severity: "HIGH",
	}

	scanner.AddSignature(sig)

	db := scanner.GetDatabase()
	if len(db.Signatures) != 1 {
		t.Errorf("Expected 1 signature, got %d", len(db.Signatures))
	}

	// ID should be auto-generated
	if db.Signatures[0].ID == "" {
		t.Error("Expected auto-generated ID")
	}
}
