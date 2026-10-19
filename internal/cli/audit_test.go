package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// writeGoFile writes src to dir/sub/x.go and returns the path.
func writeGoFile(t *testing.T, dir, sub, src string) string {
	t.Helper()
	p := filepath.Join(dir, sub, "x.go")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeClaude serves the Claude messages API: the injection sentinel's check
// passes, and each audit request, recorded in requests, gets reply.
func fakeClaude(t *testing.T, reply string) (url string, requests *[]map[string]any) {
	t.Helper()
	var auditRequests []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		system, _ := json.Marshal(req["system"])
		text := reply
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
	t.Cleanup(ts.Close)
	return ts.URL, &auditRequests
}

// An audit with a Claude model sends the flagged function's source on both
// sides and offers the audit tools; the model's verdict decides the exit
// code.
func TestRunAudit_SendsSourceAndTools(t *testing.T) {
	dir := t.TempDir()
	old := writeGoFile(t, dir, "old", "package x\n\nfunc Handle(s string) int { return len(s) }\n")
	risky := writeGoFile(t, dir, "risky", "package x\n\nimport \"os/exec\"\n\nfunc Handle(s string) int { exec.Command(s).Run(); return len(s) }\n")
	url, auditRequests := fakeClaude(t, `{"verdict": "LIE", "evidence": "Handle now runs a command"}`)

	var buf strings.Builder
	code, err := RunAudit(&buf, old, risky, "minor cleanup", "k", models.ModelClaudeOpus, url, true)
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
	if len(*auditRequests) != 1 {
		t.Fatalf("%d audit requests; want 1", len(*auditRequests))
	}
	req := (*auditRequests)[0]
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

// A new linkname directive is high-risk with no function to show. Audit
// sends it as evidence, and without a key to verify it fails, rather than
// passing the change. A removed one scores 0 and passes.
func TestRunAudit_SendsLinkname(t *testing.T) {
	const directive = "//go:linkname n example.invalid/q.secret"
	dir := t.TempDir()
	old := writeGoFile(t, dir, "old", "package x\n\nimport _ \"unsafe\"\n\nvar n int\n")
	linked := writeGoFile(t, dir, "new", "package x\n\nimport _ \"unsafe\"\n\n"+directive+"\nvar n int\n")
	url, auditRequests := fakeClaude(t, `{"verdict": "SUSPICIOUS", "evidence": "n is now another package's variable"}`)

	var buf strings.Builder
	code, err := RunAudit(&buf, old, linked, "minor cleanup", "k", models.ModelClaudeOpus, url, true)
	if err != nil {
		t.Fatalf("RunAudit: %v", err)
	}
	if code != 1 || len(*auditRequests) != 1 {
		t.Fatalf("exit %d after %d audit requests; want 1 after 1\n%s", code, len(*auditRequests), buf.String())
	}
	payload, _ := json.Marshal((*auditRequests)[0]["messages"])
	for _, want := range []string{linked + ": " + directive, `\"structural_delta\": \"linkname\"`} {
		if !strings.Contains(string(payload), want) {
			t.Errorf("audit payload lacks %q:\n%s", want, payload)
		}
	}

	buf.Reset()
	code, err = RunAudit(&buf, linked, old, "minor cleanup", "k", models.ModelClaudeOpus, url, true)
	if err != nil {
		t.Fatalf("RunAudit, directive removed: %v", err)
	}
	if code != 0 || len(*auditRequests) != 1 {
		t.Errorf("directive removed: exit %d, %d audit requests in all; want 0 and still 1\n%s", code, len(*auditRequests), buf.String())
	}

	buf.Reset()
	code, err = RunAudit(&buf, old, linked, "minor cleanup", "", models.ModelGeminiFlash, "", true)
	if err != nil {
		t.Fatalf("RunAudit without a key: %v", err)
	}
	if code != 1 || !strings.Contains(buf.String(), "need LLM verification") {
		t.Errorf("without a key: exit %d\n%s\nwant 1 and a request for verification", code, buf.String())
	}
}
