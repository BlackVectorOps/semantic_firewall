package detection

// SignatureDatabase represents the malware signature database.
type SignatureDatabase struct {
	Version     string      `json:"version"`
	Description string      `json:"description"`
	Signatures  []Signature `json:"signatures"`
}

// Signature represents a single malware signature entry.
type Signature struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	Description         string              `json:"description"`
	Severity            string              `json:"severity"`
	Category            string              `json:"category"`
	TopologyHash        string              `json:"topology_hash"`
	FuzzyHash           string              `json:"fuzzy_hash,omitempty"`
	EntropyScore        float64             `json:"entropy_score"`
	EntropyTolerance    float64             `json:"entropy_tolerance"`
	NodeCount           int                 `json:"node_count"`
	LoopDepth           int                 `json:"loop_depth"`
	IdentifyingFeatures IdentifyingFeatures `json:"identifying_features"`
	Metadata            SignatureMetadata   `json:"metadata"`
}

// IdentifyingFeatures captures behavioral markers for detection.
type IdentifyingFeatures struct {
	RequiredCalls  []string          `json:"required_calls,omitempty"`
	OptionalCalls  []string          `json:"optional_calls,omitempty"`
	StringPatterns []string          `json:"string_patterns,omitempty"`
	ControlFlow    *ControlFlowHints `json:"control_flow,omitempty"`
}

// ControlFlowHints captures control flow patterns.
type ControlFlowHints struct {
	HasInfiniteLoop   bool `json:"has_infinite_loop,omitempty"`
	HasReconnectLogic bool `json:"has_reconnect_logic,omitempty"`
}

// SignatureMetadata contains provenance information.
type SignatureMetadata struct {
	Author     string   `json:"author"`
	Created    string   `json:"created"`
	References []string `json:"references,omitempty"`
}

// ScanResult represents a match between analyzed code and a signature.
type ScanResult struct {
	SignatureID     string       `json:"signature_id"`
	SignatureName   string       `json:"signature_name"`
	Severity        string       `json:"severity"`
	MatchedFunction string       `json:"matched_function"`
	Confidence      float64      `json:"confidence"` // 0.0 to 1.0
	MatchDetails    MatchDetails `json:"match_details"`
}

// MatchDetails provides granular information about the match.
type MatchDetails struct {
	TopologyMatch      bool     `json:"topology_match"`
	EntropyMatch       bool     `json:"entropy_match"`
	CallsMatched       []string `json:"calls_matched"`
	CallsMissing       []string `json:"calls_missing"`
	StringsMatched     []string `json:"strings_matched"`
	TopologySimilarity float64  `json:"topology_similarity"`
	EntropyDistance    float64  `json:"entropy_distance"`
}
