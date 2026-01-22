// -- ./cmd/sfw/cmd_audit.go --
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// -- AUDIT COMMAND --

func runAudit(w io.Writer, oldFile, newFile, commitMsg, apiKey, model, apiBase string) (int, error) {
	diff, err := computeDiff(oldFile, newFile)
	if err != nil {
		return 0, fmt.Errorf("diff computation failed: %w", err)
	}

	var evidence []AuditEvidence
	for _, fn := range diff.Functions {
		// Use constants from constants.go (centralized configuration)
		if fn.RiskScore >= RiskScoreHigh {
			var ops string
			// Security Fix: Prevent OOM by not joining a massive slice before checking length.
			if len(fn.AddedOps) > MaxDiffOpsDisplay {
				ops = fmt.Sprintf("%s (+%d more)", strings.Join(fn.AddedOps[:MaxDiffOpsDisplay], ", "), len(fn.AddedOps)-MaxDiffOpsDisplay)
			} else {
				ops = strings.Join(fn.AddedOps, ", ")
			}

			// Now correctly references the AuditEvidence struct in types.go.
			evidence = append(evidence, AuditEvidence{
				Function:        fn.Function,
				RiskScore:       fn.RiskScore,
				StructuralDelta: fn.TopologyDelta,
				AddedOperations: ops,
			})
		}
	}

	highRiskDetected := len(evidence) > 0

	output := AuditOutput{
		Inputs: AuditInputs{
			CommitMessage: commitMsg,
		},
		RiskFilter: RiskFilterStats{
			HighRiskDetected: highRiskDetected,
			EvidenceCount:    len(evidence),
		},
	}

	if highRiskDetected {
		// Aegis: If high risk is detected, we MUST verify.
		// If the verification fails due to network/API error, we treat it as an ERROR verdict.
		result, err := callLLM(commitMsg, evidence, apiKey, model, apiBase)
		if err != nil {
			// FAIL-CLOSED: System errors fail the audit to prevent bypassing security.
			output.Output = LLMResult{
				Verdict:  VerdictError,
				Evidence: fmt.Sprintf("Verification Failed: %v", err),
			}
		} else {
			output.Output = result
		}
	} else {
		// Automatic pass only if no structural risk.
		output.Output = LLMResult{
			Verdict:  VerdictMatch,
			Evidence: "Automatic Pass: No structural escalation detected.",
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return 0, fmt.Errorf("json encode failed: %w", err)
	}

	// Security Policy: Non zero exit code for LIE or ERROR.
	if output.Output.Verdict == VerdictLie || output.Output.Verdict == VerdictError {
		return 1, nil
	}

	return 0, nil
}
