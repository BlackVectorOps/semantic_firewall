package models

import "time"

//-- Section --

const (
	// FilePermReadWrite defines standard non-executable file permissions.
	FilePermReadWrite = 0644
	// FilePermSecure enforces strict owner-only access to prevent local privilege escalation or data leakage.
	FilePermSecure = 0600
	// prevents memory exhaustion attacks by capping the size of files loaded into the AST.
	MaxSourceFileSize = 10 * 1024 * 1024 // 10 MB
	// limits the buffer size for LLM responses to mitigate potential DoS from upstream providers.
	MaxAPIResponseSize = 5 * 1024 * 1024 // 5 MB
	// controls the verbosity of the diff output to keep CLI reports readable.
	MaxDiffOpsDisplay = 10

	// limits the number of attempts to reach an API before conceding failure.
	MaxHTTPRetries = 3
	// provides the starting point for exponential backoff calculations.
	BaseRetryDelay = 500 * time.Millisecond
	// prevents backoff times from growing indefinitely and stalling the execution pipeline.
	MaxRetryDelay = 5 * time.Second
	// sets a hard deadline for network requests to prevent lingering or "zombie" connections.
	HTTPClientTimeout = 120 * time.Second
	// acts as a circuit breaker for the entire operation to ensure the tool exits within a predictable window.
	GlobalScanTimeout = 300 * time.Second

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

	// multimodal reasoning model.
	ModelGeminiPro = "gemini-3-pro-preview"
	// high speed, low latency analysis for large codebases.
	ModelGeminiFlash = "gemini-2.5-flash"
	// frontier OpenAI reasoning models.
	ModelGPT5_2 = "gpt-5.2"
	// optimized specifically for deep static analysis tasks.
	ModelGPT5_2_Codex = "gpt-5.2-codex"
	// legacy flagship for general purpose diffing.
	ModelGPT4o = "gpt-4o"
	// used for cost effective initial triaging.
	ModelGPT4oMini = "gpt-4o-mini"

	//  portable, human readable storage format for scan results.
	BackendJSON = "json"
	//  high performance, LSM tree based storage for large scale analysis history.
	BackendPebbleDB = "pebbledb"
)
