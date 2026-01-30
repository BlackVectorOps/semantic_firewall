// -- internal/cli/audit.go --
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	// FIX: Pass os.Stderr instead of nil to capture sandbox runtime errors.
	err := SandboxExec(sb, &outputBuf, os.Stderr, "diff", args, cleanOld, cleanNew)
	if err != nil {
		// FAIL-CLOSED: Infrastructure error must not allow bypass.
		return 1, fmt.Errorf("audit failed during sandboxed diff: %w", err)
	}

	var diffOutput models.DiffOutput
	if err := json.Unmarshal(outputBuf.Bytes(), &diffOutput); err != nil {
		// FAIL-CLOSED: Malformed JSON suggests exploit attempt or tool crash.
		return 1, fmt.Errorf("failed to parse sandboxed diff output (invalid JSON): %w", err)
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

	output.Output = models.LLMResult{
		Verdict:  models.VerdictError,
		Evidence: "Analysis incomplete.",
	}

	if highRiskDetected {
		result, err := llm.CallLLM(commitMsg, evidence, apiKey, model, apiBase)
		if err != nil {
			output.Output = models.LLMResult{
				Verdict:  models.VerdictError,
				Evidence: fmt.Sprintf("Verification Failed: %v", err),
			}
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

	// FAIL-CLOSED: Strict Verdict Enforcement
	switch output.Output.Verdict {
	case models.VerdictMatch, models.StatusPreserved:
		return 0, nil
	case models.VerdictLie, models.VerdictSuspicious, models.VerdictError:
		return 1, nil
	default:
		return 1, fmt.Errorf("unknown verdict received: %s", output.Output.Verdict)
	}
}
