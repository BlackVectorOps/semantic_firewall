package llm

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/BlackVectorOps/semantic_firewall/v5/pkg/models"
)

const (
	oldHandle = "package x\n\nfunc Handle(s string) int { return len(s) }\n"
	newHandle = "package x\n\nimport \"os/exec\"\n\nfunc Handle(s string) int {\n\texec.Command(s).Run()\n\treturn len(s)\n}\n"
)

func handleDiff() *models.DiffOutput {
	return &models.DiffOutput{
		Functions: []models.FunctionDiff{{
			Function: "Handle", Status: models.StatusModified, RiskScore: 15,
			TopologyDelta: "Capability+exec(os/exec.Command)",
			AddedOps:      []string{"call os/exec.Command", "call (*os/exec.Cmd).Run"},
		}},
		TopologyMatches: []models.TopologyMatchInfo{{OldFunction: "Handle", NewFunction: "Handle", Similarity: 0.8, MatchedByName: true}},
	}
}

func handleContext() *AuditContext {
	return NewAuditContext("old/x.go", []byte(oldHandle), "new/x.go", []byte(newHandle), handleDiff())
}

func call(t *testing.T, c *AuditContext, tool string, input map[string]any) (string, bool) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return c.Call(tool, raw)
}

func TestAuditTools_ServeSourceAndDiff(t *testing.T) {
	c := handleContext()

	text, isErr := call(t, c, "function_source", map[string]any{"function": "Handle", "side": "new"})
	if isErr || !strings.Contains(text, "6: \texec.Command(s).Run()") {
		t.Errorf("function_source new = %q (error %v)", text, isErr)
	}
	text, isErr = call(t, c, "function_source", map[string]any{"function": "Handle", "side": "old"})
	if isErr || !strings.Contains(text, "return len(s)") || strings.Contains(text, "exec") {
		t.Errorf("function_source old = %q (error %v)", text, isErr)
	}

	text, isErr = call(t, c, "function_diff", map[string]any{"function": "Handle"})
	if isErr || !strings.Contains(text, "call (*os/exec.Cmd).Run") || !strings.Contains(text, `"similarity": 0.8`) {
		t.Errorf("function_diff = %q (error %v); want every added op and the topology match", text, isErr)
	}

	text, isErr = call(t, c, "file_context", map[string]any{"side": "new", "line": 3, "radius": 1})
	if isErr || text != "2: \n3: import \"os/exec\"\n4: \n" {
		t.Errorf("file_context = %q (error %v)", text, isErr)
	}

	text, isErr = call(t, c, "list_functions", map[string]any{"side": "old"})
	if isErr || text != "Handle lines 3-3\n" {
		t.Errorf("list_functions = %q (error %v)", text, isErr)
	}

	text, isErr = call(t, c, "callees", map[string]any{"function": "Handle", "side": "new"})
	if isErr || text != "_.Run\nexec.Command\nlen\n" {
		t.Errorf("callees = %q (error %v)", text, isErr)
	}
	text, isErr = call(t, c, "callers", map[string]any{"function": "Handle", "side": "new"})
	if isErr || !strings.Contains(text, "nothing in the new file calls Handle") {
		t.Errorf("callers = %q (error %v)", text, isErr)
	}
}

// Every failure is reported to the model as a tool error, never as a panic
// or an empty success.
func TestAuditTools_Errors(t *testing.T) {
	c := handleContext()
	c.Old = nil // the file was added
	cases := []struct {
		tool  string
		input map[string]any
		want  string
	}{
		{"function_source", map[string]any{"function": "Handle", "side": "old"}, "no old file"},
		{"function_source", map[string]any{"function": "Nope", "side": "new"}, `no declaration named "Nope"`},
		{"function_source", map[string]any{"function": "Handle", "side": "sideways"}, `side must be "old" or "new"`},
		{"function_diff", map[string]any{"function": "Nope"}, "reports no function"},
		{"file_context", map[string]any{"side": "new", "line": 99}, "outside the new file"},
		{"teleport", map[string]any{}, "unknown tool"},
	}
	for _, tc := range cases {
		text, isErr := call(t, c, tc.tool, tc.input)
		if !isErr || !strings.Contains(text, tc.want) {
			t.Errorf("%s%v = %q (error %v); want an error containing %q", tc.tool, tc.input, text, isErr, tc.want)
		}
	}
	if text, isErr := c.Call("function_source", json.RawMessage(`{"function": 7`)); !isErr || !strings.Contains(text, "invalid input") {
		t.Errorf("malformed input = %q (error %v)", text, isErr)
	}
}

func TestAuditTools_Bounds(t *testing.T) {
	var b strings.Builder
	b.WriteString("package x\n\nfunc Big() {\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "\tprintln(%d) // padding padding padding padding padding\n", i)
	}
	b.WriteString("}\n")
	c := NewAuditContext("", nil, "x.go", []byte(b.String()), &models.DiffOutput{})

	text, isErr := call(t, c, "function_source", map[string]any{"function": "Big", "side": "new"})
	if isErr || len(text) > models.MaxToolResultBytes+100 || !strings.Contains(text, "cut at the tool result limit") {
		t.Errorf("function_source of a huge function: %d bytes, error %v, cut marker %v", len(text), isErr, strings.Contains(text, "cut at"))
	}

	text, isErr = call(t, c, "file_context", map[string]any{"side": "new", "line": 1000, "radius": 10000})
	if isErr || strings.Count(text, "\n") != 2*models.MaxFileContextRadius+1 {
		t.Errorf("file_context radius is not clamped: %d lines", strings.Count(text, "\n"))
	}

	_, newSrc := c.InlineSource(models.FunctionDiff{Function: "Big"})
	if n := strings.Count(newSrc, "\n"); n != models.MaxInlineSourceLines+1 || !strings.Contains(newSrc, "more lines; function_source") {
		t.Errorf("InlineSource = %d lines; want %d plus the cut marker", n, models.MaxInlineSourceLines)
	}
}

// A renamed pair is served by either half, on the side it exists on.
func TestAuditTools_RenamedFunction(t *testing.T) {
	c := NewAuditContext("old.go", []byte("package x\n\nfunc A() {}\n"), "new.go", []byte("package x\n\nfunc B() {}\n"),
		&models.DiffOutput{Functions: []models.FunctionDiff{{Function: "A → B", Status: models.StatusRenamed}}})

	oldSrc, newSrc := c.InlineSource(models.FunctionDiff{Function: "A → B"})
	if !strings.Contains(oldSrc, "func A()") || !strings.Contains(newSrc, "func B()") {
		t.Errorf("InlineSource(A → B) = %q, %q", oldSrc, newSrc)
	}
	if text, isErr := call(t, c, "function_source", map[string]any{"function": "A → B", "side": "new"}); isErr || !strings.Contains(text, "func B()") {
		t.Errorf("function_source(A → B, new) = %q (error %v)", text, isErr)
	}
	if text, isErr := call(t, c, "function_diff", map[string]any{"function": "B"}); isErr || !strings.Contains(text, `"status": "renamed"`) {
		t.Errorf("function_diff(B) = %q (error %v)", text, isErr)
	}
}
