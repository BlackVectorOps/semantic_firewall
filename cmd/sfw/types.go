// -- ./cmd/sfw/types.go --
package main

import (
	semanticfw "github.com/BlackVectorOps/semantic_firewall/v2"
)

// -- Data Structures: Fingerprinting & Diffing --

// FunctionFingerprint represents the JSON output for a single function's analysis.
type FunctionFingerprint struct {
	Function    string `json:"function"`
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
}

// FileOutput represents the comprehensive JSON output for a single source file.
type FileOutput struct {
	File         string                  `json:"file"`
	Functions    []FunctionFingerprint   `json:"functions"`
	ScanResults  []semanticfw.ScanResult `json:"scan_results,omitempty"` // Security alerts from the unified pipeline
	ErrorMessage string                  `json:"error,omitempty"`
}

// DiffOutput represents the JSON output for a semantic comparison between two files.
type DiffOutput struct {
	OldFile         string              `json:"old_file"`
	NewFile         string              `json:"new_file"`
	Summary         DiffSummary         `json:"summary"`
	Functions       []FunctionDiff      `json:"functions"`
	ErrorMessage    string              `json:"error,omitempty"`
	TopologyMatches []TopologyMatchInfo `json:"topology_matches,omitempty"`
}

// TopologyMatchInfo describes a pair of functions matched by structural similarity rather than name.
type TopologyMatchInfo struct {
	OldFunction   string  `json:"old_function"`
	NewFunction   string  `json:"new_function"`
	Similarity    float64 `json:"similarity"`
	MatchedByName bool    `json:"matched_by_name"`
	OldTopology   string  `json:"old_topology,omitempty"`
	NewTopology   string  `json:"new_topology,omitempty"`
}

// DiffSummary provides aggregate statistics for a diff operation.
type DiffSummary struct {
	TotalFunctions     int     `json:"total_functions"`
	Preserved          int     `json:"preserved"`
	Modified           int     `json:"modified"`
	Added              int     `json:"added"`
	Removed            int     `json:"removed"`
	SemanticMatchPct   float64 `json:"semantic_match_pct"`
	TopologyMatchedPct float64 `json:"topology_matched_pct,omitempty"` // Percentage of functions matched by structure
	RenamedFunctions   int     `json:"renamed_functions,omitempty"`    // Count of functions matched by topology, implying a rename
	HighRiskChanges    int     `json:"high_risk_changes,omitempty"`    // Count of changes introducing new calls, loops, or complexity
}

// FunctionDiff represents the semantic difference details for a single function.
type FunctionDiff struct {
	Function         string   `json:"function"`
	Status           string   `json:"status"` // "preserved", "modified", "added", "removed"
	FingerprintMatch bool     `json:"fingerprint_match"`
	OldFingerprint   string   `json:"old_fingerprint,omitempty"`
	NewFingerprint   string   `json:"new_fingerprint,omitempty"`
	MatchedNodes     int      `json:"matched_nodes,omitempty"`
	AddedOps         []string `json:"added_ops,omitempty"`
	RemovedOps       []string `json:"removed_ops,omitempty"`
	RiskScore        int      `json:"risk_score,omitempty"`     // Calculated risk; higher indicates more suspicious changes
	TopologyDelta    string   `json:"topology_delta,omitempty"` // Summary of structural changes (e.g., "Loops+1")
}

// -- Data Structures: Audit & LLM Integration --

// AuditOutput encapsulates the result of a semantic audit, including LLM verification.
type AuditOutput struct {
	Inputs     AuditInputs     `json:"inputs"`
	RiskFilter RiskFilterStats `json:"risk_filter"`
	Output     LLMResult       `json:"output"`
}

// AuditInputs captures the context provided to the audit command.
type AuditInputs struct {
	CommitMessage string `json:"commit_message"`
}

// RiskFilterStats tracks if the deterministic logic found enough evidence to trigger an LLM check.
type RiskFilterStats struct {
	HighRiskDetected bool `json:"high_risk_detected"`
	EvidenceCount    int  `json:"evidence_count"`
}

// LLMResult represents the final verdict from the AI model or simulator.
type LLMResult struct {
	Verdict  string `json:"verdict"`  // MATCH, SUSPICIOUS, LIE, ERROR
	Evidence string `json:"evidence"` // Reasoning provided by the LLM
}

// AuditEvidence describes specific high risk changes passed to the LLM for analysis.
// This is the canonical definition used by cmd_audit.go.
type AuditEvidence struct {
	Function        string `json:"function"`
	RiskScore       int    `json:"risk_score"`
	StructuralDelta string `json:"structural_delta"`
	AddedOperations string `json:"added_operations"`
}

// -- Data Structures: OpenAI API (2026 Standards) --

// OpenAIResponsesRequest replaces the legacy Chat Completions structure.
// Ref: Chapter 2.1 - Migration to Responses API
type OpenAIResponsesRequest struct {
	Model          string         `json:"model"`
	Items          []OpenAIItem   `json:"items"`
	Store          bool           `json:"store"` // Server side state (Chapter 2.2)
	ResponseFormat *OpenAIRespFmt `json:"response_format,omitempty"`
}

// OpenAIItem replaces "Message" to support multimodal and tool contexts.
type OpenAIItem struct {
	Type    string `json:"type"` // "message"
	Role    string `json:"role"` // "developer", "user", "assistant"
	Content string `json:"content"`
}

// OpenAIResponsesResponse represents the response from the Responses API.
type OpenAIResponsesResponse struct {
	Items []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"items"`
}

// OpenAIRespFmt specifies the desired output format (e.g., JSON).
type OpenAIRespFmt struct {
	Type string `json:"type"`
}

// -- Data Structures: Gemini API (v1 Standard) --
// Used for internal/raw handling if SDK is bypassed.

type GeminiRequest struct {
	Contents          []GeminiContent  `json:"contents"`
	SystemInstruction *GeminiContent   `json:"systemInstruction,omitempty"`
	GenerationConfig  *GeminiGenConfig `json:"generationConfig,omitempty"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"` // "user", "model"
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiGenConfig struct {
	ResponseMimeType string `json:"responseMimeType"` // "application/json"
}

// -- Data Structures: Sentinel --

// SentinelResponse captures the verdict from the pre flight injection check.
type SentinelResponse struct {
	Safe     bool   `json:"safe"`
	Analysis string `json:"analysis,omitempty"`
}

// -- Data Structures: Scan Command --

type ScanOptions struct {
	DBPath    string
	Threshold float64
	ExactOnly bool
	ScanDeps  bool
	DepsDepth string
}

type ScanOutput struct {
	Target       string                  `json:"target"`
	Database     string                  `json:"database"`
	Backend      string                  `json:"backend"`
	Threshold    float64                 `json:"threshold"`
	TotalScanned int                     `json:"total_functions_scanned"`
	DepsScanned  int                     `json:"dependencies_scanned,omitempty"`
	Alerts       []semanticfw.ScanResult `json:"alerts"`
	Summary      ScanSummary             `json:"summary"`
	ScannedDeps  []string                `json:"scanned_dependencies,omitempty"`
	Error        string                  `json:"error,omitempty"`
}

type ScanSummary struct {
	CriticalAlerts int `json:"critical"`
	HighAlerts     int `json:"high"`
	MediumAlerts   int `json:"medium"`
	LowAlerts      int `json:"low"`
	TotalAlerts    int `json:"total_alerts"`
}
