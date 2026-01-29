package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BlackVectorOps/semantic_firewall/v3/pkg/models"
)

// -- Helpers --

// mockResponse constructs a strictly valid JSON response to prevent test flakiness.
// We use json.Marshal here instead of fmt.Sprintf to avoid accidental JSON injection
// or malformed escaping when dealing with complex evidence strings.
func mockResponse(w http.ResponseWriter, sentinelSafe bool, verdict string) {
	// 1. Construct the inner content object first
	innerContent := map[string]interface{}{}
	if !sentinelSafe {
		innerContent["safe"] = false
		innerContent["analysis"] = "Injection Detected"
	} else if verdict != "" {
		innerContent["verdict"] = verdict
		innerContent["evidence"] = "Test"
	} else {
		innerContent["safe"] = true
	}

	// 2. Marshal the inner content to handle all escaping (quotes, newlines) automatically
	contentBytes, err := json.Marshal(innerContent)
	if err != nil {
		// If the test helper fails, panic immediately to stop the suite
		panic(fmt.Sprintf("failed to marshal mock content: %v", err))
	}

	// 3. Construct the outer Gemini/LLM response structure
	// We preserve the structure expected by the client parser
	response := map[string]interface{}{
		"items": []map[string]interface{}{
			{
				"role": "model",
				"content": []map[string]interface{}{
					{
						"type": "text",
						// string(contentBytes) ensures we pass the JSON string exactly as the LLM would
						"text": string(contentBytes),
					},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(fmt.Sprintf("failed to write mock response: %v", err))
	}
}

// -- Fuzz Tests --

func FuzzCleanJSONMarkdown(f *testing.F) {
	f.Add(`{"a":1}`)
	f.Add("```json\n{\"a\":1}\n```")
	f.Add("Text ```{\"a\":1}```")

	f.Fuzz(func(t *testing.T, input string) {
		cleanJSONMarkdown(input)
		// Property: Function should never panic and should handle arbitrary UTF-8
		// In a real scenario, we might also check that the output is valid JSON
		// if the input contained valid JSON structures.
	})
}

// -- Unit Tests --

func TestCleanJSONMarkdown_Strategies(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"Simple", `{"a":1}`, `{"a":1}`},
		{"Markdown", "```json\n{\"a\":1}\n```", `{"a":1}`},
		{
			"NestedFences",
			// Input has backticks, which is fine in a double-quoted string
			"```json\n{\"evidence\": \"Use ```code```\"}\n```",
			// We must use double quotes here because raw strings (backticks) cannot contain backticks.
			// This matches the expected output after markdown stripping.
			"{\"evidence\": \"Use ```code```\"}",
		},
		{"Conversational", "Here is JSON:\n```\n{\"a\":1}\n```", `{"a":1}`},
		{"Fallback", "Text {\"a\":1} Text", `{"a":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cleanJSONMarkdown(tc.input)
			if got != tc.want {
				t.Errorf("Got %s, Want %s", got, tc.want)
			}
		})
	}
}

func TestCallLLM_FullFlow(t *testing.T) {
	// Ensure nonce generation is deterministic for this snapshot
	origNonce := generateNonceFunc
	generateNonceFunc = func(l int) (string, error) { return "TESTNONCE", nil }
	defer func() { generateNonceFunc = origNonce }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Check for the presence of the sentinel to simulate the two-stage check (Safety -> Logic)
		if strings.Contains(string(body), "Sentinel") {
			mockResponse(w, true, "")
		} else {
			mockResponse(w, true, "MATCH")
		}
	}))
	defer ts.Close()

	res, err := CallLLM("msg", nil, "k", models.ModelGPT5_2, ts.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if res.Verdict != "MATCH" {
		t.Errorf("Verdict mismatch: %s", res.Verdict)
	}
}

func TestCallLLM_RetryLogic(t *testing.T) {
	// Eliminate test latency by mocking the sleep duration
	origSleep := sleepFunc
	sleepFunc = func(d time.Duration) {}
	defer func() { sleepFunc = origSleep }()

	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(429)
			return
		}
		mockResponse(w, true, "MATCH")
	}))
	defer ts.Close()

	ctx := context.Background()
	_, err := executeOpenAIRaw(ctx, "sys", "user", "k", models.ModelGPT5_2, ts.URL)
	if err != nil {
		t.Fatalf("Expected success after retry, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestCallLLM_InjectionDefense(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a prompt injection detection by the Sentinel
		mockResponse(w, false, "")
	}))
	defer ts.Close()

	res, err := CallLLM("attack", nil, "k", models.ModelGPT5_2, ts.URL)
	if err != nil {
		t.Fatalf("Should not error on logic detection: %v", err)
	}
	if res.Verdict != models.VerdictLie {
		t.Errorf("Expected LIE, got %s", res.Verdict)
	}
	if !strings.Contains(res.Evidence, "Injection Detected") {
		t.Errorf("Evidence should reflect injection")
	}
}

func TestBuildModernPrompts_Nonce(t *testing.T) {
	origNonce := generateNonceFunc
	defer func() { generateNonceFunc = origNonce }()

	// Verify that the nonce is correctly embedded in the delimiter
	generateNonceFunc = func(l int) (string, error) { return "UNIQUE1", nil }
	_, p1, _ := buildModernPrompts("test", nil)

	if !strings.Contains(p1, "### BEGIN DATA [UNIQUE1] ###") {
		t.Error("Prompt missing secure nonce delimiter")
	}
}
