package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

// An audit with a Claude model sends the flagged function's source on both
// sides and offers the audit tools; the model's verdict decides the exit
// code.
func TestRunAudit_SendsSourceAndTools(t *testing.T) {
	dir := t.TempDir()
	write := func(sub, src string) string {
		p := filepath.Join(dir, sub, "x.go")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := write("old", "package x\n\nfunc Handle(s string) int { return len(s) }\n")
	risky := write("risky", "package x\n\nimport \"os/exec\"\n\nfunc Handle(s string) int { exec.Command(s).Run(); return len(s) }\n")

	var auditRequests []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		system, _ := json.Marshal(req["system"])
		text := `{"verdict": "LIE", "evidence": "Handle now runs a command"}`
		if strings.Contains(string(system), "Sentinel") {
			text = `{"safe": true, "analysis": "clean"}`
		} else {
			auditRequests = append(auditRequests, req)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "msg", "type": "message", "role": "assistant", "model": models.ModelClaudeOpus,
			"content": []map[string]any{{"type": "text", "text": text}}, "stop_reason": "end_turn",
			"usage": map[string]any{"input_tokens": 1, "output_tokens": 1},
		})
	}))
	defer ts.Close()

	var buf strings.Builder
	code, err := RunAudit(&buf, old, risky, "minor cleanup", "k", models.ModelClaudeOpus, ts.URL, true)
	if err != nil {
		t.Fatalf("RunAudit: %v", err)
	}
	var out models.AuditOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("parse audit output: %v\n%s", err, buf.String())
	}
	if code != 1 || out.Output.Verdict != models.VerdictLie {
		t.Errorf("exit %d verdict %s; want 1 LIE", code, out.Output.Verdict)
	}
	if len(auditRequests) != 1 {
		t.Fatalf("%d audit requests; want 1", len(auditRequests))
	}
	req := auditRequests[0]
	payload, _ := json.Marshal(req["messages"])
	for _, want := range []string{`old_source`, `return len(s) }`, `new_source`, `exec.Command(s).Run()`, `\"status\": \"modified\"`} {
		if !strings.Contains(string(payload), want) {
			t.Errorf("audit payload lacks %q:\n%s", want, payload)
		}
	}
	tools, _ := req["tools"].([]any)
	names := map[string]bool{}
	for _, tool := range tools {
		m, _ := tool.(map[string]any)
		names[m["name"].(string)] = true
	}
	if !names["function_source"] || !names["file_context"] {
		t.Errorf("audit request tools = %v; want the audit tools", names)
	}
}
