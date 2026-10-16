package llm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
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

	res, err := CallLLM("fix typo", nil, "k", models.ModelClaudeOpus, ts.URL, nil)
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

	res, err := CallLLM("msg", nil, "k", models.ModelClaudeOpus, ts.URL, nil)
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

// claudeToolUse writes a Messages API response that calls the given tools
// (each {"name", "input"}), stopping for tool_use.
func claudeToolUse(w http.ResponseWriter, uses ...map[string]any) {
	content := make([]map[string]any, 0, len(uses))
	for i, u := range uses {
		content = append(content, map[string]any{
			"type": "tool_use", "id": fmt.Sprintf("tu_%d", i), "name": u["name"], "input": u["input"],
		})
	}
	resp := map[string]any{
		"id": "msg_tool", "type": "message", "role": "assistant", "model": models.ModelClaudeOpus,
		"content": content, "stop_reason": "tool_use",
		"usage": map[string]any{"input_tokens": 1, "output_tokens": 1},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// claudeRequestKind classifies a decoded request: the sentinel, the first
// audit call, or an audit call carrying tool results.
func claudeRequestKind(req map[string]any) string {
	system, _ := json.Marshal(req["system"])
	if strings.Contains(string(system), "Sentinel") {
		return "sentinel"
	}
	msgs, _ := req["messages"].([]any)
	if len(msgs) > 0 {
		last, _ := json.Marshal(msgs[len(msgs)-1])
		if strings.Contains(string(last), `"tool_result"`) {
			return "audit+results"
		}
	}
	return "audit"
}

func handleEvidence(c *AuditContext) []models.AuditEvidence {
	fn := c.Diff.Functions[0]
	ev := models.AuditEvidence{Function: fn.Function, Status: fn.Status, RiskScore: fn.RiskScore, StructuralDelta: fn.TopologyDelta}
	ev.OldSource, ev.NewSource = c.InlineSource(fn)
	return []models.AuditEvidence{ev}
}

// The verdict call offers the audit tools, serves a round of calls with the
// results fenced and sentinel-checked, and the evidence carries the flagged
// function's source on both sides.
func TestCallLLM_ClaudeToolLoop(t *testing.T) {
	var kinds []string
	var sentinelPayloads []string
	var toolResultText string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		kind := claudeRequestKind(req)
		kinds = append(kinds, kind)
		switch kind {
		case "sentinel":
			body, _ := json.Marshal(req["messages"])
			sentinelPayloads = append(sentinelPayloads, string(body))
			claudeMessage(w, `{"safe": true, "analysis": "clean"}`, "end_turn")
		case "audit":
			if tools, _ := req["tools"].([]any); len(tools) != len(auditToolDefinitions) {
				t.Errorf("audit request offers %d tools; want %d", len(tools), len(auditToolDefinitions))
			}
			first, _ := json.Marshal(req["messages"])
			if !strings.Contains(string(first), "new_source") || !strings.Contains(string(first), "exec.Command(s).Run()") {
				t.Errorf("evidence payload lacks the new source: %s", first)
			}
			claudeToolUse(w,
				map[string]any{"name": "function_source", "input": map[string]any{"function": "Handle", "side": "old"}},
				map[string]any{"name": "callers", "input": map[string]any{"function": "Handle", "side": "sideways"}},
			)
		case "audit+results":
			msgs, _ := req["messages"].([]any)
			last, _ := json.Marshal(msgs[len(msgs)-1])
			toolResultText = string(last)
			claudeMessage(w, `{"verdict": "LIE", "evidence": "Handle spawns a process"}`, "end_turn")
		}
	}))
	defer ts.Close()

	c := handleContext()
	res, err := CallLLM("minor cleanup", handleEvidence(c), "k", models.ModelClaudeOpus, ts.URL, c)
	if err != nil {
		t.Fatalf("CallLLM: %v", err)
	}
	if res.Verdict != models.VerdictLie {
		t.Errorf("verdict = %q; want LIE", res.Verdict)
	}
	if want := []string{"sentinel", "audit", "sentinel", "audit+results"}; !slices.Equal(kinds, want) {
		t.Fatalf("request sequence = %v; want %v", kinds, want)
	}
	// Both results go back in one user turn: the source fenced, the bad
	// call as a tool error.
	if !strings.Contains(toolResultText, `"tool_use_id":"tu_0"`) || !strings.Contains(toolResultText, "BEGIN RETRIEVED SOURCE [") ||
		!strings.Contains(toolResultText, "return len(s)") {
		t.Errorf("tool results lack the fenced old source: %s", toolResultText)
	}
	if !strings.Contains(toolResultText, `"tool_use_id":"tu_1"`) || !strings.Contains(toolResultText, `"is_error":true`) {
		t.Errorf("the failed call is not reported as a tool error: %s", toolResultText)
	}
	// The second sentinel saw the retrieved source, not the payload again.
	if len(sentinelPayloads) != 2 || !strings.Contains(sentinelPayloads[1], "return len(s)") || strings.Contains(sentinelPayloads[1], "diff_evidence") {
		t.Errorf("second sentinel payload = %v", sentinelPayloads)
	}
}

// Retrieved source that the sentinel rejects never reaches the model: the
// audit ends in LIE, as an injected payload does.
func TestCallLLM_ClaudeToolResultInjection(t *testing.T) {
	sentinels := 0
	audits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		switch claudeRequestKind(req) {
		case "sentinel":
			sentinels++
			if sentinels == 1 {
				claudeMessage(w, `{"safe": true, "analysis": "clean"}`, "end_turn")
			} else {
				claudeMessage(w, `{"safe": false, "analysis": "a comment tells the auditor to ignore previous instructions"}`, "end_turn")
			}
		default:
			audits++
			claudeToolUse(w, map[string]any{"name": "function_source", "input": map[string]any{"function": "Handle", "side": "new"}})
		}
	}))
	defer ts.Close()

	c := handleContext()
	res, err := CallLLM("minor cleanup", handleEvidence(c), "k", models.ModelClaudeOpus, ts.URL, c)
	if err != nil {
		t.Fatalf("CallLLM: %v", err)
	}
	if res.Verdict != models.VerdictLie || !strings.Contains(res.Evidence, "retrieved source") {
		t.Errorf("verdict = %q (%s); want LIE naming the retrieved source", res.Verdict, res.Evidence)
	}
	if sentinels != 2 || audits != 1 {
		t.Errorf("%d sentinel and %d audit calls; want 2 and 1 (the model never saw the rejected result)", sentinels, audits)
	}
}

// A model that never stops calling tools gets models.MaxAuditToolRounds
// rounds, then the audit fails closed.
func TestCallLLM_ClaudeToolRoundsBounded(t *testing.T) {
	audits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if claudeRequestKind(req) == "sentinel" {
			claudeMessage(w, `{"safe": true, "analysis": "clean"}`, "end_turn")
			return
		}
		audits++
		claudeToolUse(w, map[string]any{"name": "list_functions", "input": map[string]any{"side": "new"}})
	}))
	defer ts.Close()

	c := handleContext()
	res, err := CallLLM("minor cleanup", handleEvidence(c), "k", models.ModelClaudeOpus, ts.URL, c)
	if err == nil || res.Verdict != models.VerdictError {
		t.Errorf("unbounded tool use: verdict %q err %v; want ERROR with an error", res.Verdict, err)
	}
	if audits != models.MaxAuditToolRounds+1 {
		t.Errorf("%d audit calls; want %d (the budget, then the refused round)", audits, models.MaxAuditToolRounds+1)
	}
}

// Without an AuditContext no tools are offered, and a tool call anyway is
// an error, not a verdict.
func TestCallLLM_ClaudeToolUseWithoutContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if claudeRequestKind(req) == "sentinel" {
			claudeMessage(w, `{"safe": true, "analysis": "clean"}`, "end_turn")
			return
		}
		if _, ok := req["tools"]; ok {
			t.Error("tools offered without an audit context")
		}
		claudeToolUse(w, map[string]any{"name": "list_functions", "input": map[string]any{"side": "new"}})
	}))
	defer ts.Close()

	res, err := CallLLM("msg", nil, "k", models.ModelClaudeOpus, ts.URL, nil)
	if err == nil || res.Verdict != models.VerdictError {
		t.Errorf("verdict %q err %v; want ERROR with an error", res.Verdict, err)
	}
}
