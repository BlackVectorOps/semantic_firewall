package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
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

func callClaude(ctx context.Context, sysPrompt, userPayload, apiKey, model, apiBase string) (models.LLMResult, error) {
	text, err := executeClaudeRaw(ctx, sysPrompt, userPayload, apiKey, model, apiBase, auditSchema)
	if err != nil {
		return models.LLMResult{}, err
	}
	return parseLLMJSON(text)
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

func executeClaudeRaw(ctx context.Context, sysPrompt, userMsg, apiKey, model, apiBase string, schema map[string]any) (string, error) {
	opts := []option.RequestOption{option.WithMaxRetries(models.MaxHTTPRetries)}
	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}
	if apiBase != "" {
		opts = append(opts, option.WithBaseURL(apiBase))
	}
	client := anthropic.NewClient(opts...)

	resp, err := client.Beta.Messages.New(ctx, claudeRequest(sysPrompt, userMsg, model, apiBase, schema))
	if err != nil {
		return "", err
	}
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		return "", fmt.Errorf("model refused (category %q): %s", resp.StopDetails.Category, resp.StopDetails.Explanation)
	}

	var sb strings.Builder
	for _, block := range resp.Content {
		if text, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			sb.WriteString(text.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("empty response (stop reason %q)", resp.StopReason)
	}
	return sb.String(), nil
}
