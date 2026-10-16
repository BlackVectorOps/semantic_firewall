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

// Every tool on each side: the side errors, the edges of file_context and
// the empty results.
func TestAuditTools_EachToolEachSide(t *testing.T) {
	added := NewAuditContext("", nil, "new/x.go", []byte(newHandle), handleDiff())
	removed := NewAuditContext("old/x.go", []byte(oldHandle), "", nil, handleDiff())
	for _, tool := range []string{"function_source", "file_context", "list_functions", "callers", "callees"} {
		in := map[string]any{"function": "Handle", "side": "old", "line": 1}
		if text, isErr := call(t, added, tool, in); !isErr || !strings.Contains(text, "no old file") {
			t.Errorf("%s on an added file's old side = %q (error %v)", tool, text, isErr)
		}
		in["side"] = "new"
		if text, isErr := call(t, removed, tool, in); !isErr || !strings.Contains(text, "no new file") {
			t.Errorf("%s on a removed file's new side = %q (error %v)", tool, text, isErr)
		}
	}

	c := handleContext()
	lines := strings.Count(newHandle, "\n") + 1
	if text, isErr := call(t, c, "file_context", map[string]any{"side": "new", "line": 1, "radius": 1}); isErr || text != "1: package x\n2: \n" {
		t.Errorf("file_context at line 1 = %q (error %v)", text, isErr)
	}
	if text, isErr := call(t, c, "file_context", map[string]any{"side": "new", "line": lines, "radius": 1}); isErr || !strings.HasPrefix(text, fmt.Sprintf("%d: }\n", lines-1)) {
		t.Errorf("file_context at the last line = %q (error %v)", text, isErr)
	}
	if text, isErr := call(t, c, "file_context", map[string]any{"side": "new", "line": 0}); !isErr || !strings.Contains(text, "outside") {
		t.Errorf("file_context at line 0 = %q (error %v)", text, isErr)
	}

	// A missing or zero radius is the default of 20 lines each side.
	var b strings.Builder
	b.WriteString("package x\n")
	for i := 0; i < 100; i++ {
		b.WriteString("// filler\n")
	}
	long := NewAuditContext("", nil, "x.go", []byte(b.String()), &models.DiffOutput{})
	for _, in := range []map[string]any{{"side": "new", "line": 50}, {"side": "new", "line": 50, "radius": 0}} {
		if text, _ := call(t, long, "file_context", in); strings.Count(text, "\n") != 41 || !strings.HasPrefix(text, "30: ") {
			t.Errorf("file_context %v = %d lines from %q; want 41 from line 30", in, strings.Count(text, "\n"), text[:min(len(text), 8)])
		}
	}

	empty := NewAuditContext("", nil, "x.go", []byte("package x\n"), &models.DiffOutput{})
	if text, isErr := call(t, empty, "list_functions", map[string]any{"side": "new"}); isErr || text != "no function declarations" {
		t.Errorf("list_functions of a file without functions = %q (error %v)", text, isErr)
	}
	leaf := NewAuditContext("", nil, "x.go", []byte("package x\n\nfunc Leaf() {}\n\nfunc Root() { Leaf() }\n"), &models.DiffOutput{})
	if text, isErr := call(t, leaf, "callees", map[string]any{"function": "Leaf", "side": "new"}); isErr || text != "no calls" {
		t.Errorf("callees of a leaf = %q (error %v)", text, isErr)
	}
	if text, isErr := call(t, leaf, "callers", map[string]any{"function": "Leaf", "side": "new"}); isErr || text != "Root\n" {
		t.Errorf("callers of Leaf = %q (error %v)", text, isErr)
	}
	if text, isErr := call(t, leaf, "callees", map[string]any{"function": "Nope", "side": "new"}); !isErr || !strings.Contains(text, `no declaration named "Nope"`) {
		t.Errorf("callees of a missing function = %q (error %v)", text, isErr)
	}
}

// A closure name is answered with its enclosing declaration, the note on a
// line of its own above the source.
func TestAuditTools_ClosureNote(t *testing.T) {
	c := NewAuditContext("", nil, "x.go", []byte("package x\n\nfunc F() { g := func() {}; g() }\n"), &models.DiffOutput{})
	for _, tool := range []string{"function_source", "callees"} {
		text, isErr := call(t, c, tool, map[string]any{"function": "F$1", "side": "new"})
		if isErr || !strings.HasPrefix(text, "F$1 is inside F; showing the whole declaration.\n") || strings.Contains(text, "declaration.3:") {
			t.Errorf("%s(F$1) = %q (error %v)", tool, text, isErr)
		}
	}
	_, src := c.InlineSource(models.FunctionDiff{Function: "F$1"})
	if !strings.HasPrefix(src, "F$1 is inside F; showing the whole declaration.\n3: func F()") {
		t.Errorf("InlineSource(F$1) = %q", src)
	}
}

// The inline source is cut only past models.MaxInlineSourceLines, and the
// marker counts the lines left out.
func TestAuditTools_InlineSourceBoundary(t *testing.T) {
	body := func(lines int) string {
		var b strings.Builder
		b.WriteString("package x\n\nfunc F() {\n")
		for i := 0; i < lines-2; i++ {
			b.WriteString("\tprintln()\n")
		}
		b.WriteString("}\n")
		return b.String()
	}
	for _, tc := range []struct{ lines, cut int }{
		{models.MaxInlineSourceLines, 0},
		{models.MaxInlineSourceLines + 1, 1},
		{models.MaxInlineSourceLines + 7, 7},
	} {
		c := NewAuditContext("", nil, "x.go", []byte(body(tc.lines)), &models.DiffOutput{})
		_, src := c.InlineSource(models.FunctionDiff{Function: "F"})
		shown := strings.Count(src, "\n")
		marker := fmt.Sprintf("[... %d more lines;", tc.cut)
		switch {
		case tc.cut == 0 && (shown != tc.lines || strings.Contains(src, "more lines")):
			t.Errorf("%d-line function: %d lines shown, cut marker %v; want all, no marker", tc.lines, shown, strings.Contains(src, "more lines"))
		case tc.cut > 0 && (shown != models.MaxInlineSourceLines+1 || !strings.Contains(src, marker)):
			t.Errorf("%d-line function: %d lines shown; want %d and %q", tc.lines, shown, models.MaxInlineSourceLines, marker)
		}
	}
}

// function_diff picks the topology match of the function asked for, and
// needs a diff.
func TestAuditTools_FunctionDiffMatch(t *testing.T) {
	d := handleDiff()
	d.TopologyMatches = append([]models.TopologyMatchInfo{{OldFunction: "Other", NewFunction: "Other", Similarity: 0.1}}, d.TopologyMatches...)
	c := NewAuditContext("old/x.go", []byte(oldHandle), "new/x.go", []byte(newHandle), d)
	if text, isErr := call(t, c, "function_diff", map[string]any{"function": "Handle"}); isErr || !strings.Contains(text, `"similarity": 0.8`) {
		t.Errorf("function_diff(Handle) = %q (error %v); want Handle's own match", text, isErr)
	}
	c.Diff = nil
	if text, isErr := call(t, c, "function_diff", map[string]any{"function": "Handle"}); !isErr || !strings.Contains(text, "no diff output") {
		t.Errorf("function_diff without a diff = %q (error %v)", text, isErr)
	}
	// An empty input is the zero input, not a parse error.
	c.Diff = d
	if text, isErr := c.Call("function_diff", nil); !isErr || !strings.Contains(text, "reports no function") {
		t.Errorf("function_diff with no input = %q (error %v)", text, isErr)
	}
}

// The old half of a renamed pair is served on the old side.
func TestAuditTools_RenamedOldSide(t *testing.T) {
	c := NewAuditContext("old.go", []byte("package x\n\nfunc A() {}\n\nfunc UseA() { A() }\n"), "new.go", []byte("package x\n\nfunc B() {}\n"), &models.DiffOutput{})
	if text, isErr := call(t, c, "callers", map[string]any{"function": "A → B", "side": "old"}); isErr || text != "UseA\n" {
		t.Errorf("callers(A → B, old) = %q (error %v)", text, isErr)
	}
}
