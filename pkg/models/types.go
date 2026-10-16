package models

import (
	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/detection"
)

// -- Diff & Fingerprinting --

type DiffOutput struct {
	OldFile         string              `json:"old_file"`
	NewFile         string              `json:"new_file"`
	Summary         DiffSummary         `json:"summary"`
	Functions       []FunctionDiff      `json:"functions"`
	ErrorMessage    string              `json:"error,omitempty"`
	TopologyMatches []TopologyMatchInfo `json:"topology_matches,omitempty"`
}

type TopologyMatchInfo struct {
	OldFunction   string  `json:"old_function"`
	NewFunction   string  `json:"new_function"`
	Similarity    float64 `json:"similarity"`
	MatchedByName bool    `json:"matched_by_name"`
	OldTopology   string  `json:"old_topology,omitempty"`
	NewTopology   string  `json:"new_topology,omitempty"`
}

type DiffSummary struct {
	TotalFunctions     int     `json:"total_functions"`
	Preserved          int     `json:"preserved"`
	Modified           int     `json:"modified"`
	Added              int     `json:"added"`
	Removed            int     `json:"removed"`
	SemanticMatchPct   float64 `json:"semantic_match_pct"`
	TopologyMatchedPct float64 `json:"topology_matched_pct,omitempty"`
	RenamedFunctions   int     `json:"renamed_functions,omitempty"`
	HighRiskChanges    int     `json:"high_risk_changes,omitempty"`
}

type FunctionDiff struct {
	Function         string   `json:"function"`
	Status           string   `json:"status"`
	FingerprintMatch bool     `json:"fingerprint_match"`
	OldFingerprint   string   `json:"old_fingerprint,omitempty"`
	NewFingerprint   string   `json:"new_fingerprint,omitempty"`
	MatchedNodes     int      `json:"matched_nodes,omitempty"`
	AddedOps         []string `json:"added_ops,omitempty"`
	RemovedOps       []string `json:"removed_ops,omitempty"`
	RiskScore        int      `json:"risk_score,omitempty"`
	TopologyDelta    string   `json:"topology_delta,omitempty"`
}

// -- CLI & Scan --

type FunctionFingerprint struct {
	Function    string `json:"function"`
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
}

type FileOutput struct {
	File         string                 `json:"file"`
	Functions    []FunctionFingerprint  `json:"functions"`
	ScanResults  []detection.ScanResult `json:"scan_results,omitempty"`
	ErrorMessage string                 `json:"error,omitempty"`
}

type ScanOptions struct {
	DBPath    string
	Threshold float64
	ExactOnly bool
	ScanDeps  bool
	DepsDepth string
}

type ScanOutput struct {
	Target       string                 `json:"target"`
	Database     string                 `json:"database"`
	Backend      string                 `json:"backend"`
	Threshold    float64                `json:"threshold"`
	TotalScanned int                    `json:"total_functions_scanned"`
	DepsScanned  int                    `json:"dependencies_scanned,omitempty"`
	Alerts       []detection.ScanResult `json:"alerts"`
	Summary      ScanSummary            `json:"summary"`
	ScannedDeps  []string               `json:"scanned_dependencies,omitempty"`
}

type ScanSummary struct {
	CriticalAlerts int `json:"critical"`
	HighAlerts     int `json:"high"`
	MediumAlerts   int `json:"medium"`
	LowAlerts      int `json:"low"`
	TotalAlerts    int `json:"total_alerts"`
}

// -- Audit & LLM --

type AuditOutput struct {
	Inputs     AuditInputs     `json:"inputs"`
	RiskFilter RiskFilterStats `json:"risk_filter"`
	Output     LLMResult       `json:"output"`
}

type AuditInputs struct {
	CommitMessage string `json:"commit_message"`
}

type RiskFilterStats struct {
	HighRiskDetected bool `json:"high_risk_detected"`
	EvidenceCount    int  `json:"evidence_count"`
}

type LLMResult struct {
	Verdict  string `json:"verdict"`
	Evidence string `json:"evidence"`
}

type AuditEvidence struct {
	Function        string `json:"function"`
	RiskScore       int    `json:"risk_score"`
	StructuralDelta string `json:"structural_delta"`
	AddedOperations string `json:"added_operations"`
}

// -- OpenAI / Gemini API Types --

// OpenAIResponsesRequest is the body of a POST /v1/responses call.
type OpenAIResponsesRequest struct {
	Model string               `json:"model"`
	Input []OpenAIInputMessage `json:"input"`
	Store bool                 `json:"store"`
	Text  *OpenAITextConfig    `json:"text,omitempty"`
}

// OpenAIInputMessage is one message of a Responses API input list.
type OpenAIInputMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAITextConfig selects the Responses API output format.
type OpenAITextConfig struct {
	Format OpenAITextFormat `json:"format"`
}

type OpenAITextFormat struct {
	Type string `json:"type"`
}

// OpenAIResponsesResponse is the subset of a Responses API result the client
// reads: the output items, of which assistant "message" items carry the text.
type OpenAIResponsesResponse struct {
	Output []OpenAIOutputItem `json:"output"`
}

type OpenAIOutputItem struct {
	Type    string              `json:"type"`
	Role    string              `json:"role"`
	Content []OpenAIContentPart `json:"content"`
}

// OpenAIContentPart is one part of an output message: "output_text" carries
// Text, "refusal" carries Refusal.
type OpenAIContentPart struct {
	Type    string `json:"type"`
	Text    string `json:"text"`
	Refusal string `json:"refusal,omitempty"`
}

type SentinelResponse struct {
	Safe     bool   `json:"safe"`
	Analysis string `json:"analysis,omitempty"`
}
