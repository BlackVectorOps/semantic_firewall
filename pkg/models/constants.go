package models

import "time"

//-- Section --

const (
	// prevents memory exhaustion attacks by capping the size of files loaded into the AST.
	MaxSourceFileSize = 10 * 1024 * 1024 // 10 MB
	// limits the buffer size for LLM responses to mitigate potential DoS from upstream providers.
	MaxAPIResponseSize = 5 * 1024 * 1024 // 5 MB
	// controls the verbosity of the diff output to keep CLI reports readable.
	MaxDiffOpsDisplay = 10
	// caps the length of the LLM "evidence" summary. A response longer than a
	// short plain-text rationale indicates the model strayed from the output
	// protocol (e.g. echoing the payload or injected instructions back).
	MaxEvidenceRunes = 4000
	// bounds the source of one side of a flagged function in the audit
	// payload; the rest is a tool call away.
	MaxInlineSourceLines = 120
	// caps one tool result the auditor retrieves.
	MaxToolResultBytes = 16 * 1024
	// caps the lines on each side of a file_context request.
	MaxFileContextRadius = 60
	// caps the tool-call rounds of one audit; the model answers within them
	// or the audit fails closed.
	MaxAuditToolRounds = 8

	// limits the number of attempts to reach an API before conceding failure.
	MaxHTTPRetries = 3
	// provides the starting point for exponential backoff calculations.
	BaseRetryDelay = 500 * time.Millisecond
	// prevents backoff times from growing indefinitely and stalling the execution pipeline.
	MaxRetryDelay = 5 * time.Second
	// bounds one audit's LLM verification: every request and retry in it.
	LLMCallTimeout = 300 * time.Second
	// GlobalScanTimeout is LLMCallTimeout under its old name.
	//
	// Deprecated: Use LLMCallTimeout. It bounds an audit's LLM calls, not a
	// scan.
	//
	//go:fix inline
	GlobalScanTimeout = LLMCallTimeout

	// is the minimum confidence score required to suggest a structural match.
	DefaultTopologyMatchThreshold = 0.6
	// defines the baseline for flagging potentially malicious deviations.
	DefaultScanThreshold = 0.75

	// is the threshold where a function's delta is marked for manual peer review.
	RiskScoreHigh = 10
	// is the baseline penalty applied to any entirely new logic introduced in a diff.
	BaseRiskAddedFunc = 5

	//  no change detected in the target block.
	StatusPreserved = "preserved"
	//  logic changes within an existing function signature.
	StatusModified = "modified"
	//  new logic that did not exist in the baseline.
	StatusAdded = "added"
	// indicates logic that has been purged from the source.
	StatusRemoved = "removed"
	//  symbol name change where the underlying AST structure remains identical.
	StatusRenamed = "renamed"

	//  the analysis engine could not determine the structural change type.
	TopoDeltaUnknown = "Unknown"
	//  flags an entirely new function entry point.
	TopoDeltaNew = "NewFunction"
	//  confirms that while text may have changed, the control flow remains the same.
	TopoDeltaNone = "NoStructuralChange"
	//  alerts the auditor to new concurrent execution paths.
	TopoDeltaGoroutine = "AddedGoroutine"
	//  flags new deferred cleanup logic which could be used for resource masking.
	TopoDeltaDefer = "AddedDefer"
	//  indicates the introduction of unhandled error states.
	TopoDeltaPanic = "AddedPanic"

	//  confirms the LLM and AST analysis are in agreement.
	VerdictMatch = "MATCH"
	//  suggests that the LLM analysis found logic the AST delta did not anticipate.
	VerdictSuspicious = "SUSPICIOUS"
	//  indicates a high confidence that the LLM response is hallucinating or being deceptive.
	VerdictLie = "LIE"
	//  indicates a failure in the analysis pipeline itself.
	VerdictError = "ERROR"

	//  vulnerabilities that allow for immediate code execution or data exfiltration.
	SeverityCritical = "CRITICAL"
	//  significant security regressions.
	SeverityHigh = "HIGH"
	//  moderate risk changes or policy violations.
	SeverityMedium = "MEDIUM"
	//  minor issues or code quality concerns.
	SeverityLow = "LOW"

	// default audit model.
	ModelClaudeOpus = "claude-opus-5-5"
	// multimodal reasoning model.
	ModelGeminiPro = "gemini-3-pro-preview"
	// high speed, low latency analysis for large codebases.
	ModelGeminiFlash = "gemini-2.5-flash"
	// frontier OpenAI reasoning models.
	ModelGPT5_2 = "gpt-5.2"

	//  portable, human readable storage format for scan results.
	BackendJSON = "json"
	//  high performance, LSM tree based storage for large scale analysis history.
	BackendPebbleDB = "pebbledb"
)
