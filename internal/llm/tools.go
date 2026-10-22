package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v7/pkg/models"
)

// AuditContext is what the auditor may read while it judges a diff: the two
// sides as text and the full diff output. The model reaches it through the
// read-only tools in auditToolDefinitions; nothing in it runs code or
// touches the file system after construction.
type AuditContext struct {
	Old, New *SourceIndex
	Diff     *models.DiffOutput
}

// NewAuditContext indexes the two sides of a diff. A missing side (an added
// or removed file) is passed as nil content.
func NewAuditContext(oldPath string, oldSrc []byte, newPath string, newSrc []byte, diff *models.DiffOutput) *AuditContext {
	c := &AuditContext{Diff: diff}
	if oldSrc != nil {
		c.Old = NewSourceIndex(oldPath, oldSrc)
	}
	if newSrc != nil {
		c.New = NewSourceIndex(newPath, newSrc)
	}
	return c
}

// splitRenamed returns the old and new halves of a diff function name: a
// renamed or re-numbered function is reported as "old → new".
func splitRenamed(name string) (oldName, newName string) {
	if i := strings.Index(name, " → "); i >= 0 {
		return name[:i], name[i+len(" → "):]
	}
	return name, name
}

// InlineSource returns the bounded source of both sides of the function fn
// reports on, for the evidence payload. A side longer than
// models.MaxInlineSourceLines is cut with a marker, so the model knows to
// ask for the rest.
func (c *AuditContext) InlineSource(fn models.FunctionDiff) (oldSrc, newSrc string) {
	oldName, newName := splitRenamed(fn.Function)
	return c.boundedSource(c.Old, oldName), c.boundedSource(c.New, newName)
}

func (c *AuditContext) boundedSource(idx *SourceIndex, name string) string {
	fn, note, ok := idx.Lookup(name)
	if !ok {
		return ""
	}
	end := fn.End
	cut := ""
	if n := fn.End - fn.Start + 1; n > models.MaxInlineSourceLines {
		end = fn.Start + models.MaxInlineSourceLines - 1
		cut = fmt.Sprintf("[... %d more lines; function_source returns the whole declaration]\n", n-models.MaxInlineSourceLines)
	}
	if note != "" {
		note += "\n"
	}
	return note + idx.Lines(fn.Start, end) + cut
}

// auditToolDefinition describes one tool, provider-neutrally: name,
// description and JSON Schema for the input.
type auditToolDefinition struct {
	Name, Description string
	Schema            map[string]any
}

var sideProperty = map[string]any{
	"type":        "string",
	"enum":        []string{"old", "new"},
	"description": "Which side of the diff: the old file or the new file.",
}

var functionProperty = map[string]any{
	"type":        "string",
	"description": "A function name as the diff reports it: F, (*T).M, F$1 for a closure. Either half of a renamed pair \"a → b\" works.",
}

func objectSchema(required []string, props map[string]any) map[string]any {
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"required":             required,
		"additionalProperties": false,
	}
}

var auditToolDefinitions = []auditToolDefinition{
	{
		Name:        "function_source",
		Description: "The full declaration of a function on one side of the diff, with line numbers. A closure name returns its enclosing declaration.",
		Schema:      objectSchema([]string{"function", "side"}, map[string]any{"function": functionProperty, "side": sideProperty}),
	},
	{
		Name:        "function_diff",
		Description: "The deterministic analysis of one function: status, risk score, topology delta, every added and removed operation, and the topology fingerprints of both sides.",
		Schema:      objectSchema([]string{"function"}, map[string]any{"function": functionProperty}),
	},
	{
		Name:        "file_context",
		Description: "The lines around a line of one side of the diff (imports, comments, surrounding declarations). radius is the number of lines on each side, at most 60; default 20.",
		Schema: objectSchema([]string{"side", "line"}, map[string]any{
			"side":   sideProperty,
			"line":   map[string]any{"type": "integer", "description": "1-based line number."},
			"radius": map[string]any{"type": "integer", "description": "Lines on each side of line."},
		}),
	},
	{
		Name:        "list_functions",
		Description: "Every function and method declared on one side of the diff, with its line range.",
		Schema:      objectSchema([]string{"side"}, map[string]any{"side": sideProperty}),
	},
	{
		Name:        "callers",
		Description: "The functions in the same file whose body calls the named function, on one side of the diff. Syntactic: a method is matched by its method name.",
		Schema:      objectSchema([]string{"function", "side"}, map[string]any{"function": functionProperty, "side": sideProperty}),
	},
	{
		Name:        "callees",
		Description: "The calls a function's body makes, as written, on one side of the diff. Syntactic: see function_diff for what the analysis says a call reaches.",
		Schema:      objectSchema([]string{"function", "side"}, map[string]any{"function": functionProperty, "side": sideProperty}),
	},
}

// toolInput is the union of every tool's input.
type toolInput struct {
	Function string `json:"function"`
	Side     string `json:"side"`
	Line     int    `json:"line"`
	Radius   int    `json:"radius"`
}

// Call runs the named tool on input and returns its text and whether that
// text is an error message. Output is bounded by models.MaxToolResultBytes.
func (c *AuditContext) Call(name string, input json.RawMessage) (text string, isError bool) {
	text, err := c.call(name, input)
	if err != nil {
		return err.Error(), true
	}
	if len(text) > models.MaxToolResultBytes {
		text = text[:models.MaxToolResultBytes] + "\n[... output cut at the tool result limit]\n"
	}
	return text, false
}

func (c *AuditContext) call(name string, raw json.RawMessage) (string, error) {
	var in toolInput
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return "", fmt.Errorf("invalid input for %s: %v", name, err)
		}
	}
	switch name {
	case "function_source":
		idx, err := c.side(in.Side)
		if err != nil {
			return "", err
		}
		fn, note, err := lookupSide(idx, in.Side, in.Function)
		if err != nil {
			return "", err
		}
		if note != "" {
			note += "\n"
		}
		return note + idx.Source(fn), nil

	case "function_diff":
		return c.functionDiff(in.Function)

	case "file_context":
		idx, err := c.side(in.Side)
		if err != nil {
			return "", err
		}
		if in.Line < 1 || in.Line > idx.LineCount() {
			return "", fmt.Errorf("line %d is outside the %s file (%d lines)", in.Line, in.Side, idx.LineCount())
		}
		radius := in.Radius
		if radius <= 0 {
			radius = 20
		}
		if radius > models.MaxFileContextRadius {
			radius = models.MaxFileContextRadius
		}
		return idx.Lines(in.Line-radius, in.Line+radius), nil

	case "list_functions":
		idx, err := c.side(in.Side)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, fn := range idx.Functions() {
			fmt.Fprintf(&b, "%s lines %d-%d\n", fn.Name, fn.Start, fn.End)
		}
		if b.Len() == 0 {
			return "no function declarations", nil
		}
		return b.String(), nil

	case "callers":
		idx, err := c.side(in.Side)
		if err != nil {
			return "", err
		}
		name := sideName(in.Side, in.Function)
		callers := idx.Callers(name)
		if len(callers) == 0 {
			return fmt.Sprintf("nothing in the %s file calls %s", in.Side, name), nil
		}
		return strings.Join(callers, "\n") + "\n", nil

	case "callees":
		idx, err := c.side(in.Side)
		if err != nil {
			return "", err
		}
		fn, note, err := lookupSide(idx, in.Side, in.Function)
		if err != nil {
			return "", err
		}
		if note != "" {
			note += "\n"
		}
		if len(fn.Callees) == 0 {
			return note + "no calls", nil
		}
		return note + strings.Join(fn.Callees, "\n") + "\n", nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// side returns the index for "old" or "new", or an error naming the
// missing side.
func (c *AuditContext) side(side string) (*SourceIndex, error) {
	switch side {
	case "old":
		if c.Old == nil {
			return nil, fmt.Errorf("there is no old file: the file was added")
		}
		return c.Old, nil
	case "new":
		if c.New == nil {
			return nil, fmt.Errorf("there is no new file: the file was removed")
		}
		return c.New, nil
	}
	return nil, fmt.Errorf("side must be \"old\" or \"new\", not %q", side)
}

// sideName picks the half of a renamed pair that exists on side.
func sideName(side, name string) string {
	oldName, newName := splitRenamed(name)
	if side == "old" {
		return oldName
	}
	return newName
}

func lookupSide(idx *SourceIndex, side, name string) (*sourceFunc, string, error) {
	want := sideName(side, name)
	fn, note, ok := idx.Lookup(want)
	if !ok {
		return nil, "", fmt.Errorf("no declaration named %q in the %s file; list_functions names them", want, side)
	}
	return fn, note, nil
}

// functionDiff returns the diff's record of one function and its topology
// match, as JSON.
func (c *AuditContext) functionDiff(name string) (string, error) {
	if c.Diff == nil {
		return "", fmt.Errorf("no diff output available")
	}
	oldName, newName := splitRenamed(name)
	for _, fn := range c.Diff.Functions {
		o, n := splitRenamed(fn.Function)
		if fn.Function != name && o != oldName && n != newName {
			continue
		}
		out := struct {
			models.FunctionDiff
			TopologyMatch *models.TopologyMatchInfo `json:"topology_match,omitempty"`
		}{FunctionDiff: fn}
		for i := range c.Diff.TopologyMatches {
			m := &c.Diff.TopologyMatches[i]
			if m.OldFunction == o || m.NewFunction == n {
				out.TopologyMatch = m
				break
			}
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	return "", fmt.Errorf("the diff reports no function named %q", name)
}
