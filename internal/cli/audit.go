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

	"github.com/BlackVectorOps/semantic_firewall/v7/internal/llm"
	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// -- AUDIT COMMAND --

func RunAudit(w io.Writer, oldFile, newFile, commitMsg, apiKey, model, apiBase string, noSandbox bool) (int, error) {
	cleanOld := filepath.Clean(oldFile)
	cleanNew := filepath.Clean(newFile)
	sb := RealSandboxer{}

	var outputBuf bytes.Buffer

	// When the caller opted out of sandboxing -- or when we're already running
	// inside one (nested CI containers, runsc-in-runsc) -- skip SandboxExec and
	// invoke the diff logic directly. The previous unconditional SandboxExec
	// failed closed with "process is already sandboxed; nested sandboxing is
	// not supported" and left audit unusable in any pre-sandboxed environment.
	if noSandbox || sb.IsSandboxed() {
		if err := RunDiffLogic(RealFileSystem{}, &outputBuf, cleanOld, cleanNew); err != nil {
			return 1, fmt.Errorf("audit failed during diff: %w", err)
		}
	} else {
		args := []string{cleanOld, cleanNew}
		// The sandbox runtime reports its own failures on stderr.
		err := SandboxExec(sb, &outputBuf, os.Stderr, "diff", args, cleanOld, cleanNew)
		if err != nil {
			// FAIL-CLOSED: Infrastructure error must not allow bypass.
			return 1, fmt.Errorf("audit failed during sandboxed diff: %w", err)
		}
	}

	var diffOutput models.DiffOutput
	if err := json.Unmarshal(outputBuf.Bytes(), &diffOutput); err != nil {
		// FAIL-CLOSED: Malformed JSON suggests exploit attempt or tool crash.
		return 1, fmt.Errorf("failed to parse sandboxed diff output (invalid JSON): %w", err)
	}

	// The auditor reads the two files as text (go/parser, no toolchain), so
	// this happens outside the sandbox. An unreadable side is an absent
	// side: the diff above already decided what that means.
	audit := llm.NewAuditContext(cleanOld, readSourceText(cleanOld), cleanNew, readSourceText(cleanNew), &diffOutput)

	var evidence []models.AuditEvidence
	for _, fn := range diffOutput.Functions {
		if fn.RiskScore >= models.RiskScoreHigh {
			var ops string
			if len(fn.AddedOps) > models.MaxDiffOpsDisplay {
				ops = fmt.Sprintf("%s (+%d more)", strings.Join(fn.AddedOps[:models.MaxDiffOpsDisplay], ", "), len(fn.AddedOps)-models.MaxDiffOpsDisplay)
			} else {
				ops = strings.Join(fn.AddedOps, ", ")
			}

			oldSrc, newSrc := audit.InlineSource(fn)
			evidence = append(evidence, models.AuditEvidence{
				Function:        fn.Function,
				Status:          fn.Status,
				RiskScore:       fn.RiskScore,
				StructuralDelta: fn.TopologyDelta,
				AddedOperations: ops,
				OldSource:       oldSrc,
				NewSource:       newSrc,
			})
		}
	}
	// A high-risk linkname directive has no function to show; the model
	// reads the file with its tools.
	for _, fc := range diffOutput.Unanalyzed {
		if fc.RiskScore >= models.RiskScoreHigh {
			evidence = append(evidence, models.AuditEvidence{
				Function:        fc.File,
				Status:          fc.Change,
				RiskScore:       fc.RiskScore,
				StructuralDelta: fc.Kind,
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

	if highRiskDetected && apiKey == "" && llm.RequiresAPIKey(model) {
		// FAIL-CLOSED: escalations exist but nothing can verify the claim.
		output.Output = models.LLMResult{
			Verdict:  models.VerdictError,
			Evidence: fmt.Sprintf("High-risk changes need LLM verification, but no API key was provided (set %s).", llm.APIKeyEnvVar(model)),
		}
	} else if highRiskDetected {
		result, err := llm.CallLLM(commitMsg, evidence, apiKey, model, apiBase, audit)
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

	// FAIL-CLOSED: Strict Verdict Enforcement.
	// Normalize case to stay consistent with llm.validateOutput, which accepts
	// verdicts case-insensitively; otherwise a valid lowercase "match" would
	// fall through to the default branch and be reported as an error.
	switch strings.ToUpper(output.Output.Verdict) {
	case models.VerdictMatch:
		return 0, nil
	case models.VerdictLie, models.VerdictSuspicious, models.VerdictError:
		return 1, nil
	default:
		return 1, fmt.Errorf("unknown verdict received: %s", output.Output.Verdict)
	}
}

// readSourceText reads one side of the audited diff for the auditor's
// tools, bounded by models.MaxSourceFileSize as the diff bounds its inputs.
// A missing or unreadable file is nil: that side does not exist.
func readSourceText(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, models.MaxSourceFileSize))
	if err != nil {
		return nil
	}
	return data
}
