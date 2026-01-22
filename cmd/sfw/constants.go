// -- ./cmd/sfw/constants.go --
package main

const (
	// -- Application Metadata --
	// Version is the current semantic version of the application.
	// Bump this before tagging a release.
	Version = "2.3.0"

	// -- File System Permissions --
	FilePermReadWrite = 0644
	FilePermSecure    = 0600

	// -- Resource Limits --
	// MaxSourceFileSize limits the size of files read into memory to prevent OOM DoS attacks.
	MaxSourceFileSize = 10 * 1024 * 1024 // 10 MB

	// MaxAPIResponseSize limits the size of the response body from LLM providers
	// to prevent memory exhaustion attacks from malicious endpoints.
	MaxAPIResponseSize = 5 * 1024 * 1024 // 5 MB

	// MaxDiffOpsDisplay limits the number of operations shown in the audit log
	// to prevent log flooding attacks.
	MaxDiffOpsDisplay = 10

	// -- Analysis Thresholds --
	DefaultTopologyMatchThreshold = 0.6
	DefaultScanThreshold          = 0.75

	// RiskScoreHigh determines the score at which a function diff is considered "High Risk".
	// Scores >= this value trigger the LLM audit pipeline.
	RiskScoreHigh     = 10
	BaseRiskAddedFunc = 5

	// -- Diff Statuses --
	StatusPreserved = "preserved"
	StatusModified  = "modified"
	StatusAdded     = "added"
	StatusRemoved   = "removed"
	StatusRenamed   = "renamed"

	// -- Topology Deltas --
	TopoDeltaUnknown   = "Unknown"
	TopoDeltaNew       = "NewFunction"
	TopoDeltaNone      = "NoStructuralChange"
	TopoDeltaGoroutine = "AddedGoroutine"
	TopoDeltaDefer     = "AddedDefer"
	TopoDeltaPanic     = "AddedPanic"

	// -- Audit Verdicts --
	VerdictMatch      = "MATCH"
	VerdictSuspicious = "SUSPICIOUS"
	VerdictLie        = "LIE"
	VerdictError      = "ERROR"

	// -- Severity Levels --
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"

	// -- LLM Models --
	// Gemini 3: Official Preview IDs for reasoning-heavy tasks.
	// Gemini 2.5: Official Stable IDs.
	ModelGeminiPro   = "gemini-3-pro-preview"
	ModelGeminiFlash = "gemini-2.5-flash"

	// GPT-5.2: Current SOTA for general reasoning and security analysis.
	// GPT-5.2-Codex: Specialized for code interpretation.
	ModelGPT5_2       = "gpt-5.2"
	ModelGPT5_2_Codex = "gpt-5.2-codex"
	ModelGPT4o        = "gpt-4o"
	ModelGPT4oMini    = "gpt-4o-mini"

	// -- Database Backends --
	BackendJSON     = "json"
	BackendPebbleDB = "pebbledb"
)
