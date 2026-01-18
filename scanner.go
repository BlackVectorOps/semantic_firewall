package semanticfw

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Represents the malware signature database.
type SignatureDatabase struct {
	Version     string      `json:"version"`
	Description string      `json:"description"`
	Signatures  []Signature `json:"signatures"`
}

// Represents a single malware signature entry.
type Signature struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	Description         string              `json:"description"`
	Severity            string              `json:"severity"`
	Category            string              `json:"category"`
	TopologyHash        string              `json:"topology_hash"`
	FuzzyHash           string              `json:"fuzzy_hash,omitempty"` // REMEDIATION: LSH bucket
	EntropyScore        float64             `json:"entropy_score"`
	EntropyTolerance    float64             `json:"entropy_tolerance"`
	NodeCount           int                 `json:"node_count"`
	LoopDepth           int                 `json:"loop_depth"`
	IdentifyingFeatures IdentifyingFeatures `json:"identifying_features"`
	Metadata            SignatureMetadata   `json:"metadata"`
}

// Captures behavioral markers for detection.
type IdentifyingFeatures struct {
	RequiredCalls  []string          `json:"required_calls,omitempty"`
	OptionalCalls  []string          `json:"optional_calls,omitempty"`
	StringPatterns []string          `json:"string_patterns,omitempty"`
	ControlFlow    *ControlFlowHints `json:"control_flow,omitempty"`
}

// Captures control flow patterns.
type ControlFlowHints struct {
	HasInfiniteLoop   bool `json:"has_infinite_loop,omitempty"`
	HasReconnectLogic bool `json:"has_reconnect_logic,omitempty"`
}

// Contains provenance information.
type SignatureMetadata struct {
	Author     string   `json:"author"`
	Created    string   `json:"created"`
	References []string `json:"references,omitempty"`
}

// Represents a match between analyzed code and a signature.
type ScanResult struct {
	SignatureID     string       `json:"signature_id"`
	SignatureName   string       `json:"signature_name"`
	Severity        string       `json:"severity"`
	MatchedFunction string       `json:"matched_function"`
	Confidence      float64      `json:"confidence"` // 0.0 to 1.0
	MatchDetails    MatchDetails `json:"match_details"`
}

// Provides granular information about the match.
type MatchDetails struct {
	TopologyMatch      bool     `json:"topology_match"`
	EntropyMatch       bool     `json:"entropy_match"`
	CallsMatched       []string `json:"calls_matched"`
	CallsMissing       []string `json:"calls_missing"`
	StringsMatched     []string `json:"strings_matched"`
	TopologySimilarity float64  `json:"topology_similarity"`
	EntropyDistance    float64  `json:"entropy_distance"`
}

// Performs semantic malware detection.
type Scanner struct {
	db               *SignatureDatabase
	matchThreshold   float64
	entropyTolerance float64
}

// Creates a new scanner instance.
func NewScanner() *Scanner {
	return &Scanner{
		db:               &SignatureDatabase{},
		matchThreshold:   0.75, // 75% minimum confidence for alert
		entropyTolerance: 0.5,
	}
}

// Loads signatures from a JSON file.
func (s *Scanner) LoadDatabase(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open signature database: %w", err)
	}
	defer f.Close()

	var db SignatureDatabase
	// Use Decoder for better memory efficiency with large files compared to ReadFile
	if err := json.NewDecoder(f).Decode(&db); err != nil {
		return fmt.Errorf("failed to parse signature database: %w", err)
	}

	s.db = &db
	return nil
}

// Sets the minimum confidence threshold for alerts.
func (s *Scanner) SetThreshold(threshold float64) {
	s.matchThreshold = threshold
}

// -- THE INDEXER (Lab Phase) --

// Generates a signature entry from a FunctionTopology.
// This is the "Lab Phase" where we analyze known malware to build the database.
func IndexFunction(topo *FunctionTopology, name, description, severity, category string) Signature {
	// Generate topology hash from structural features
	topoHash := generateTopologyHash(topo)
	fuzzyHash := GenerateFuzzyHash(topo)

	// Extract required calls (all unique calls made by the function)
	var requiredCalls []string
	for call := range topo.CallSignatures {
		requiredCalls = append(requiredCalls, call)
	}
	sort.Strings(requiredCalls)

	sig := Signature{
		Name:             name,
		Description:      description,
		Severity:         severity,
		Category:         category,
		TopologyHash:     topoHash,
		FuzzyHash:        fuzzyHash, // Populate LSH bucket
		EntropyScore:     topo.EntropyScore,
		EntropyTolerance: 0.5,
		NodeCount:        topo.BlockCount,
		LoopDepth:        topo.LoopCount,
		IdentifyingFeatures: IdentifyingFeatures{
			RequiredCalls:  requiredCalls,
			StringPatterns: extractStringPatterns(topo.StringLiterals),
			ControlFlow: &ControlFlowHints{
				HasInfiniteLoop:   topo.LoopCount > 0 && !topo.HasRange,
				HasReconnectLogic: hasReconnectPattern(topo),
			},
		},
	}

	return sig
}

// Creates a unique hash from structural features.
func generateTopologyHash(topo *FunctionTopology) string {
	// Build a canonical representation of the topology
	var builder strings.Builder

	// Include structural metrics
	// Use explicit string building to avoid format string overhead and risks
	builder.WriteString("P")
	builder.WriteString(strconv.Itoa(topo.ParamCount))
	builder.WriteString("R")
	builder.WriteString(strconv.Itoa(topo.ReturnCount))
	builder.WriteString("B")
	builder.WriteString(strconv.Itoa(topo.BlockCount))
	builder.WriteString("I")
	builder.WriteString(strconv.Itoa(topo.InstrCount))
	builder.WriteString("L")
	builder.WriteString(strconv.Itoa(topo.LoopCount))
	builder.WriteString("BR")
	builder.WriteString(strconv.Itoa(topo.BranchCount))

	// Include sorted call signatures
	// SECURITY FIX: Use length-prefixed encoding to prevent hash collisions.
	// Switched from fmt.Sprintf to strings.Builder/strconv for safer, distinct string construction.
	var calls []string
	for call, count := range topo.CallSignatures {
		var cb strings.Builder
		cb.WriteString(strconv.Itoa(len(call)))
		cb.WriteString(":")
		cb.WriteString(call)
		cb.WriteString(":")
		cb.WriteString(strconv.Itoa(count))
		calls = append(calls, cb.String())
	}
	sort.Strings(calls)
	builder.WriteString(strings.Join(calls, ";"))

	// Include control flow flags
	if topo.HasDefer {
		builder.WriteString("D")
	}
	if topo.HasGo {
		builder.WriteString("G")
	}
	if topo.HasSelect {
		builder.WriteString("S")
	}
	if topo.HasPanic {
		builder.WriteString("P")
	}

	// Hash the canonical form
	hash := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter hash
}

// Extracts meaningful patterns from string literals.
func extractStringPatterns(literals []string) []string {
	patterns := make(map[string]bool)
	for _, lit := range literals {
		// Skip empty or very short strings
		if len(lit) < 3 {
			continue
		}
		// Clean up the string literal (remove quotes)
		clean := strings.Trim(lit, "\"'`")
		if len(clean) >= 3 {
			patterns[clean] = true
		}
	}

	var result []string
	for p := range patterns {
		result = append(result, p)
	}
	sort.Strings(result)
	return result
}

// Detects if topology shows reconnection behavior.
func hasReconnectPattern(topo *FunctionTopology) bool {
	// Look for net.Dial + time.Sleep in a loop
	hasNetDial := false
	hasSleep := false
	for call := range topo.CallSignatures {
		if strings.Contains(call, "net.Dial") {
			hasNetDial = true
		}
		if strings.Contains(call, "time.Sleep") {
			hasSleep = true
		}
	}
	return hasNetDial && hasSleep && topo.LoopCount > 0
}

// -- THE HUNTER (Scanner Phase) --

// Checks a function topology against all signatures.
// This is the "Hunter Phase" where we scan unknown code for matches.
func (s *Scanner) ScanTopology(topo *FunctionTopology, funcName string) []ScanResult {
	if s.db == nil || len(s.db.Signatures) == 0 {
		return nil
	}

	var results []ScanResult

	for _, sig := range s.db.Signatures {
		result := s.matchSignature(topo, funcName, sig)
		if result.Confidence >= s.matchThreshold {
			results = append(results, result)
		}
	}

	// Sort by confidence (highest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results
}

// Computes how well a topology matches a signature.
func (s *Scanner) matchSignature(topo *FunctionTopology, funcName string, sig Signature) ScanResult {
	result := ScanResult{
		SignatureID:     sig.ID,
		SignatureName:   sig.Name,
		Severity:        sig.Severity,
		MatchedFunction: funcName,
	}

	var scores []float64
	details := MatchDetails{}

	// 1. Topology Hash Match (exact match = 100%, else use similarity)
	currentHash := generateTopologyHash(topo)
	if currentHash == sig.TopologyHash {
		details.TopologyMatch = true
		details.TopologySimilarity = 1.0
		scores = append(scores, 1.0)
	} else {
		// Compute structural similarity
		similarity := computeTopologySimilarity(topo, sig)
		details.TopologySimilarity = similarity
		details.TopologyMatch = similarity > 0.8
		scores = append(scores, similarity)
	}

	// 2. Entropy Match (within tolerance)
	entropyDist := EntropyDistance(topo.EntropyScore, sig.EntropyScore)
	tolerance := sig.EntropyTolerance
	if tolerance == 0 {
		tolerance = s.entropyTolerance
	}
	details.EntropyDistance = entropyDist
	details.EntropyMatch = entropyDist <= tolerance
	if details.EntropyMatch {
		// Score based on how close the entropy is
		entropyScore := 1.0 - (entropyDist / tolerance)
		scores = append(scores, entropyScore)
	} else {
		scores = append(scores, 0.5) // Partial credit if entropy is different
	}

	// 3. Call Signature Match
	if len(sig.IdentifyingFeatures.RequiredCalls) > 0 {
		callScore, matched, missing := matchCalls(topo, sig.IdentifyingFeatures.RequiredCalls)
		details.CallsMatched = matched
		details.CallsMissing = missing

		// VETO POWER: If required calls are missing, fail match
		if len(missing) > 0 {
			result.Confidence = 0.0
			result.MatchDetails = details
			return result
		}

		scores = append(scores, callScore)
	}

	// 4. String Pattern Match (bonus, not required)
	if len(sig.IdentifyingFeatures.StringPatterns) > 0 {
		stringScore, matched := matchStrings(topo, sig.IdentifyingFeatures.StringPatterns)
		details.StringsMatched = matched
		if stringScore > 0 {
			scores = append(scores, stringScore)
		}
	}

	// Calculate overall confidence
	if len(scores) > 0 {
		var total float64
		for _, sc := range scores {
			total += sc
		}
		result.Confidence = total / float64(len(scores))
	}

	result.MatchDetails = details
	return result
}

// Calculates structural similarity between topology and signature.
// Returns a value in [0, 1] where 1.0 is a perfect match.
func computeTopologySimilarity(topo *FunctionTopology, sig Signature) float64 {
	var scores []float64

	// Block count similarity (with tolerance)
	// Handle edge cases: negative or zero values
	if sig.NodeCount > 0 && topo.BlockCount >= 0 {
		blockRatio := float64(topo.BlockCount) / float64(sig.NodeCount)
		if blockRatio > 1 {
			blockRatio = 1 / blockRatio
		}
		scores = append(scores, blockRatio)
	} else if sig.NodeCount > 0 && topo.BlockCount < 0 {
		// Invalid topology - penalize heavily
		scores = append(scores, 0.0)
	}

	// Loop depth similarity
	// Handle edge cases: negative values
	if sig.LoopDepth > 0 && topo.LoopCount >= 0 {
		if topo.LoopCount == sig.LoopDepth {
			scores = append(scores, 1.0)
		} else if topo.LoopCount > 0 {
			loopRatio := float64(topo.LoopCount) / float64(sig.LoopDepth)
			if loopRatio > 1 {
				loopRatio = 1 / loopRatio
			}
			scores = append(scores, loopRatio)
		} else {
			scores = append(scores, 0.0)
		}
	} else if sig.LoopDepth > 0 && topo.LoopCount < 0 {
		// Invalid topology - penalize heavily
		scores = append(scores, 0.0)
	}

	if len(scores) == 0 {
		return 0.5
	}

	var total float64
	for _, s := range scores {
		total += s
	}
	return total / float64(len(scores))
}

// Checks how many required calls are present in the topology.
func matchCalls(topo *FunctionTopology, required []string) (score float64, matched, missing []string) {
	for _, req := range required {
		found := false
		for call := range topo.CallSignatures {
			// Only forward containment prevents false positives.
			if strings.Contains(call, req) {
				found = true
				matched = append(matched, req)
				break
			}
		}
		if !found {
			missing = append(missing, req)
		}
	}

	if len(required) > 0 {
		score = float64(len(matched)) / float64(len(required))
	}
	return
}

// Checks for string pattern matches.
func matchStrings(topo *FunctionTopology, patterns []string) (score float64, matched []string) {
	for _, pattern := range patterns {
		// Optimization: Lowercase pattern once
		patLower := strings.ToLower(pattern)
		for _, lit := range topo.StringLiterals {
			if strings.Contains(strings.ToLower(lit), patLower) {
				matched = append(matched, pattern)
				break
			}
		}
	}

	if len(patterns) > 0 {
		score = float64(len(matched)) / float64(len(patterns))
	}
	return
}

// Writes the signature database to a JSON file.
func (s *Scanner) SaveDatabase(path string) error {
	data, err := json.MarshalIndent(s.db, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal database: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// Adds a new signature to the database.
func (s *Scanner) AddSignature(sig Signature) {
	if s.db == nil {
		s.db = &SignatureDatabase{
			Version:     "1.0",
			Description: "Semantic Firewall Malware Signature Database",
		}
	}

	// Generate ID if not provided
	if sig.ID == "" {
		sig.ID = fmt.Sprintf("SFW-AUTO-%d", len(s.db.Signatures)+1)
	}

	s.db.Signatures = append(s.db.Signatures, sig)
}

// Returns the current signature database.
func (s *Scanner) GetDatabase() *SignatureDatabase {
	return s.db
}
