package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
)

// claudeMessage writes a Messages API response whose single text block is
// text, stopping for stopReason.
func claudeMessage(w http.ResponseWriter, text, stopReason string) {
	resp := map[string]any{
		"id": "msg_test", "type": "message", "role": "assistant", "model": models.ModelClaudeOpus,
		"content":     []map[string]any{{"type": "text", "text": text}},
		"stop_reason": stopReason,
		"usage":       map[string]any{"input_tokens": 1, "output_tokens": 1},
	}
	if stopReason == "refusal" {
		resp["content"] = []map[string]any{}
		resp["stop_details"] = map[string]any{"type": "refusal", "category": "cyber", "explanation": "declined"}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func TestCallLLM_ClaudeFlow(t *testing.T) {
	var requests []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %q; want /v1/messages", r.URL.Path)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		requests = append(requests, req)
		system, _ := json.Marshal(req["system"])
		if strings.Contains(string(system), "Sentinel") {
			claudeMessage(w, `{"safe": true, "analysis": "clean"}`, "end_turn")
		} else {
			claudeMessage(w, `{"verdict": "LIE", "evidence": "adds exec"}`, "end_turn")
		}
	}))
	defer ts.Close()

	res, err := CallLLM("fix typo", nil, "k", models.ModelClaudeOpus, ts.URL)
	if err != nil {
		t.Fatalf("CallLLM: %v", err)
	}
	if res.Verdict != models.VerdictLie {
		t.Errorf("verdict = %q; want LIE", res.Verdict)
	}
	if len(requests) != 2 {
		t.Fatalf("got %d requests; want sentinel + audit", len(requests))
	}
	for i, req := range requests {
		if req["model"] != models.ModelClaudeOpus {
			t.Errorf("request %d model = %v; want %s", i, req["model"], models.ModelClaudeOpus)
		}
		cfg, _ := req["output_config"].(map[string]any)
		format, _ := cfg["format"].(map[string]any)
		if cfg["effort"] != "high" || format["type"] != "json_schema" {
			t.Errorf("request %d output_config = %v; want effort high and a json_schema format", i, cfg)
		}
		if _, ok := req["fallbacks"]; ok {
			t.Errorf("request %d sent fallbacks to a custom base URL", i)
		}
	}
}

// A refusal must fail closed rather than be read as a verdict.
func TestCallLLM_ClaudeRefusalFailsClosed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claudeMessage(w, "", "refusal")
	}))
	defer ts.Close()

	res, err := CallLLM("msg", nil, "k", models.ModelClaudeOpus, ts.URL)
	if err == nil || res.Verdict != models.VerdictError {
		t.Errorf("refusal: verdict %q err %v; want ERROR with an error", res.Verdict, err)
	}
}

func TestClaudeRequest_FallbacksAndEffort(t *testing.T) {
	body := func(model, base string) map[string]any {
		raw, err := json.Marshal(claudeRequest("sys", "user", model, base, auditSchema))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		json.Unmarshal(raw, &m)
		return m
	}

	opus := body(models.ModelClaudeOpus, "")
	if opus["fallbacks"] != "default" {
		t.Errorf("first-party Opus 5.5: fallbacks = %v; want \"default\"", opus["fallbacks"])
	}
	if p := claudeRequest("s", "u", models.ModelClaudeOpus, "", auditSchema); len(p.Betas) != 1 || p.Betas[0] != "server-side-fallback-2026-07-01" {
		t.Errorf("first-party Opus 5.5: betas = %v; want the server-side fallback beta", p.Betas)
	}

	legacy := body("claude-haiku-4-5", "")
	if _, ok := legacy["fallbacks"]; ok {
		t.Error("claude-haiku-4-5: fallbacks sent to a model without fallback support")
	}
	if cfg, _ := legacy["output_config"].(map[string]any); cfg["effort"] != nil {
		t.Errorf("claude-haiku-4-5: effort %v sent to a model that rejects it", cfg["effort"])
	}
}

func TestAPIKeyResolution(t *testing.T) {
	cases := []struct {
		model, env string
		required   bool
	}{
		{"claude-opus-5-5", "ANTHROPIC_API_KEY", false},
		{"Claude-Sonnet-5-5", "ANTHROPIC_API_KEY", false},
		{"gemini-2.5-flash", "GEMINI_API_KEY", true},
		{"gpt-4o", "OPENAI_API_KEY", true},
	}
	for _, tc := range cases {
		if got := APIKeyEnvVar(tc.model); got != tc.env {
			t.Errorf("APIKeyEnvVar(%q) = %q; want %q", tc.model, got, tc.env)
		}
		if got := RequiresAPIKey(tc.model); got != tc.required {
			t.Errorf("RequiresAPIKey(%q) = %v; want %v", tc.model, got, tc.required)
		}
	}
}
