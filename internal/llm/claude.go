package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/BlackVectorOps/semantic_firewall/v6/pkg/models"
)

// claudeMaxTokens bounds a verdict response. The answer itself is a short
// JSON object, but adaptive thinking draws from the same budget.
const claudeMaxTokens = 16000

// claudeEffortModels accept output_config.effort. Older Claude models reject
// it, so it is only sent to these.
var claudeEffortModels = map[string]bool{
	"claude-fable-5-1": true, "claude-fable-5": true,
	"claude-opus-5-5": true, "claude-opus-5": true,
	"claude-opus-4-8": true, "claude-opus-4-7": true, "claude-opus-4-6": true,
	"claude-sonnet-5-5": true, "claude-sonnet-5": true, "claude-sonnet-4-6": true,
	"claude-haiku-5-5": true,
}

// claudeFallbackModels support server-side refusal fallbacks ("default"
// mode routes a declined request to a model chosen by refusal category).
var claudeFallbackModels = map[string]bool{
	"claude-fable-5-1": true, "claude-opus-5-5": true, "claude-opus-5": true, "claude-sonnet-5-5": true,
}

// auditSchema constrains the audit verdict to the protocol validateOutput
// enforces, so the reply never has to be scraped out of prose.
var auditSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"verdict":  map[string]any{"type": "string", "enum": []string{models.VerdictMatch, models.VerdictSuspicious, models.VerdictLie}},
		"evidence": map[string]any{"type": "string"},
	},
	"required":             []string{"verdict", "evidence"},
	"additionalProperties": false,
}

// sentinelSchema constrains the prompt-injection sentinel's reply.
var sentinelSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"safe":     map[string]any{"type": "boolean"},
		"analysis": map[string]any{"type": "string"},
	},
	"required":             []string{"safe", "analysis"},
	"additionalProperties": false,
}

func isClaude(model string) bool {
	return strings.HasPrefix(strings.ToLower(model), "claude")
}

// RequiresAPIKey reports whether auditing with model needs an explicit API
// key. The Anthropic SDK resolves credentials itself (ANTHROPIC_API_KEY,
// ANTHROPIC_AUTH_TOKEN, an `ant auth login` profile, workload identity), so an
// empty key is not by itself a missing credential for Claude models.
func RequiresAPIKey(model string) bool {
	return !isClaude(model)
}

// APIKeyEnvVar names the environment variable holding the API key for model's
// provider.
func APIKeyEnvVar(model string) string {
	switch {
	case isClaude(model):
		return "ANTHROPIC_API_KEY"
	case isGemini(model):
		return "GEMINI_API_KEY"
	default:
		return "OPENAI_API_KEY"
	}
}

// callClaude runs the verdict call. With an AuditContext the model may call
// the audit tools first; each round's results pass the prompt-injection
// sentinel before the model sees them, go back fenced, and the rounds are
// capped by models.MaxAuditToolRounds. A sentinel hit is returned as
// *injectionError, which CallLLM turns into the LIE verdict the payload
// sentinel gives.
func callClaude(ctx context.Context, sysPrompt, userPayload, apiKey, model, apiBase string, audit *AuditContext) (models.LLMResult, error) {
	client := newClaudeClient(apiKey, apiBase)
	params := claudeRequest(sysPrompt, userPayload, model, apiBase, auditSchema)
	if audit != nil {
		params.Tools = claudeAuditTools()
	}

	nonce, err := generateNonceFunc(8)
	if err != nil {
		return models.LLMResult{}, fmt.Errorf("nonce gen failed: %w", err)
	}

	for round := 0; ; round++ {
		resp, err := client.Beta.Messages.New(ctx, params)
		if err != nil {
			return models.LLMResult{}, err
		}
		if resp.StopReason == anthropic.BetaStopReasonRefusal {
			return models.LLMResult{}, fmt.Errorf("model refused (category %q): %s", resp.StopDetails.Category, resp.StopDetails.Explanation)
		}
		if resp.StopReason != anthropic.BetaStopReasonToolUse {
			text := claudeText(resp)
			if text == "" {
				return models.LLMResult{}, fmt.Errorf("empty response (stop reason %q)", resp.StopReason)
			}
			return parseLLMJSON(text)
		}

		// FAIL-CLOSED: a tool call the audit cannot serve, or more rounds
		// than the budget, is an ERROR, never a verdict.
		if audit == nil {
			return models.LLMResult{}, fmt.Errorf("model requested a tool but the audit offers none")
		}
		if round >= models.MaxAuditToolRounds {
			return models.LLMResult{}, fmt.Errorf("tool budget exhausted after %d rounds without a verdict", models.MaxAuditToolRounds)
		}

		params.Messages = append(params.Messages, resp.ToParam())
		var results []anthropic.BetaContentBlockParamUnion
		var retrieved strings.Builder
		for _, block := range resp.Content {
			use, ok := block.AsAny().(anthropic.BetaToolUseBlock)
			if !ok {
				continue
			}
			text, isErr := audit.Call(use.Name, json.RawMessage(use.JSON.Input.Raw()))
			if !isErr {
				retrieved.WriteString(text)
				text = fmt.Sprintf("### BEGIN RETRIEVED SOURCE [%s] ###\n%s\n### END RETRIEVED SOURCE [%s] ###", nonce, text, nonce)
			}
			results = append(results, anthropic.NewBetaToolResultBlock(use.ID, text, isErr))
		}
		if retrieved.Len() > 0 {
			safe, analysis, err := scanForInjection(ctx, retrieved.String(), apiKey, model, apiBase)
			if err != nil {
				return models.LLMResult{}, fmt.Errorf("sentinel failed on retrieved source: %w", err)
			}
			if !safe {
				return models.LLMResult{}, &injectionError{where: "retrieved source", analysis: analysis}
			}
		}
		params.Messages = append(params.Messages, anthropic.NewBetaUserMessage(results...))
	}
}

// injectionError is the sentinel's rejection of text the model was about to
// read.
type injectionError struct {
	where, analysis string
}

func (e *injectionError) Error() string {
	return fmt.Sprintf("prompt injection detected in %s: %s", e.where, e.analysis)
}

// claudeAuditTools is auditToolDefinitions as Messages API tool parameters.
func claudeAuditTools() []anthropic.BetaToolUnionParam {
	tools := make([]anthropic.BetaToolUnionParam, 0, len(auditToolDefinitions))
	for _, def := range auditToolDefinitions {
		tools = append(tools, anthropic.BetaToolUnionParam{OfTool: &anthropic.BetaToolParam{
			Name:        def.Name,
			Description: anthropic.String(def.Description),
			InputSchema: anthropic.BetaToolInputSchema(def.Schema),
		}})
	}
	return tools
}

func newClaudeClient(apiKey, apiBase string) anthropic.Client {
	opts := []option.RequestOption{option.WithMaxRetries(models.MaxHTTPRetries)}
	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}
	if apiBase != "" {
		opts = append(opts, option.WithBaseURL(apiBase))
	}
	return anthropic.NewClient(opts...)
}

// claudeText concatenates the text blocks of a response.
func claudeText(resp *anthropic.BetaMessage) string {
	var sb strings.Builder
	for _, block := range resp.Content {
		if text, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			sb.WriteString(text.Text)
		}
	}
	return sb.String()
}

// claudeRequest builds the Messages API request for one audit or sentinel
// call. Thinking is left unset: current models run adaptive thinking by
// default, and older ones run without it.
func claudeRequest(sysPrompt, userMsg, model, apiBase string, schema map[string]any) anthropic.BetaMessageNewParams {
	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: claudeMaxTokens,
		System:    []anthropic.BetaTextBlockParam{{Text: sysPrompt}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(userMsg)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Format: anthropic.BetaJSONOutputFormatParam{Schema: schema},
		},
	}
	if claudeEffortModels[model] {
		params.OutputConfig.Effort = anthropic.BetaOutputConfigEffortHigh
	}
	// Server-side fallbacks are a first-party API feature; a custom base URL
	// may be a gateway or another platform that does not accept them.
	if apiBase == "" && claudeFallbackModels[model] {
		params.Betas = append(params.Betas, anthropic.AnthropicBetaServerSideFallback2026_07_01)
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
	}
	return params
}

// executeClaudeRaw makes one tool-less call (the sentinel) and returns its
// text.
func executeClaudeRaw(ctx context.Context, sysPrompt, userMsg, apiKey, model, apiBase string, schema map[string]any) (string, error) {
	client := newClaudeClient(apiKey, apiBase)
	resp, err := client.Beta.Messages.New(ctx, claudeRequest(sysPrompt, userMsg, model, apiBase, schema))
	if err != nil {
		return "", err
	}
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		return "", fmt.Errorf("model refused (category %q): %s", resp.StopDetails.Category, resp.StopDetails.Explanation)
	}
	text := claudeText(resp)
	if text == "" {
		return "", fmt.Errorf("empty response (stop reason %q)", resp.StopReason)
	}
	return text, nil
}
