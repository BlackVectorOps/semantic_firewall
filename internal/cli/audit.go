package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v3/internal/llm"
	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/models"
)

// -- AUDIT COMMAND --

func RunAudit(w io.Writer, oldFile, newFile, commitMsg, apiKey, model, apiBase string) (int, error) {
	cleanOld := filepath.Clean(oldFile)
	cleanNew := filepath.Clean(newFile)
	args := []string{cleanOld, cleanNew}
	sb := RealSandboxer{}

	var outputBuf bytes.Buffer
	// Capture output, allow stderr to pass through for logging
	err := SandboxExec(sb, &outputBuf, nil, "diff", args, cleanOld, cleanNew)
	if err != nil {
		// Critical Fix: Audit Logic Fail-Open
		// We must return a non-zero exit code (1) if the analysis infrastructure fails.
		// Failing open here would allow attackers to bypass the gate by crashing the scanner.
		return 1, fmt.Errorf("audit failed during sandboxed diff: %w", err)
	}

	var diffOutput models.DiffOutput
	if err := json.Unmarshal(outputBuf.Bytes(), &diffOutput); err != nil {
		// Critical Fix: Lie Detector Risk / Fail-Open
		// If the JSON is malformed (e.g. oversized or contains panic text), we must fail closed.
		return 1, fmt.Errorf("failed to parse sandboxed diff output (possible exploit or runtime error): %w", err)
	}

	var evidence []models.AuditEvidence
	for _, fn := range diffOutput.Functions {
		if fn.RiskScore >= models.RiskScoreHigh {
			var ops string
			if len(fn.AddedOps) > models.MaxDiffOpsDisplay {
				ops = fmt.Sprintf("%s (+%d more)", strings.Join(fn.AddedOps[:models.MaxDiffOpsDisplay], ", "), len(fn.AddedOps)-models.MaxDiffOpsDisplay)
			} else {
				ops = strings.Join(fn.AddedOps, ", ")
			}

			evidence = append(evidence, models.AuditEvidence{
				Function:        fn.Function,
				RiskScore:       fn.RiskScore,
				StructuralDelta: fn.TopologyDelta,
				AddedOperations: ops,
			})
		}
	}

	highRiskDetected := len(evidence) > 0

	output := models.AuditOutput{
		Inputs: models.AuditInputs{
			CommitMessage: commitMsg,
		},
		RiskFilter: models.RiskFilterStats{
			HighRiskDetected: highRiskDetected,
			EvidenceCount:    len(evidence),
		},
	}

	if highRiskDetected {
		result, err := llm.CallLLM(commitMsg, evidence, apiKey, model, apiBase)
		if err != nil {
			output.Output = models.LLMResult{
				Verdict:  models.VerdictError,
				Evidence: fmt.Sprintf("Verification Failed: %v", err),
			}
			// Note: We proceed to encode the error response below, but the
			// function will return exit code 1 due to the verdict check at the end.
		} else {
			output.Output = result
		}
	} else {
		output.Output = models.LLMResult{
			Verdict:  models.VerdictMatch,
			Evidence: "Automatic Pass: No structural escalation detected.",
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return 1, fmt.Errorf("json encode failed: %w", err)
	}

	// Fail-Closed: If the verdict indicates a lie, error, or suspicion, return non-zero exit code.
	if output.Output.Verdict == models.VerdictLie || output.Output.Verdict == models.VerdictError || output.Output.Verdict == models.VerdictSuspicious {
		return 1, nil
	}

	return 0, nil
}
