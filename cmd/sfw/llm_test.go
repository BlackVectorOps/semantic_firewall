// llm_test.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// -- Integration Test: Security Pipeline --

// TestCallLLM_InjectionDefenses checks the full security pipeline:
// 1. Sentinel Pre-check (Input Filtering & Model Routing)
// 2. Fail-Secure Logic (Blocking attacks before expensive calls)
// 3. Context Scanning (Ensuring diffs are scanned)
// 4. Provider Routing (OpenAI vs Gemini)
func TestCallLLM_InjectionDefenses(t *testing.T) {
	// Shared state for the mock server to track calls
	var (
		requestCount     int
		receivedModels   []string
		receivedPayloads []string
	)

	// Mock Server acting as the LLM Provider
	// It handles both OpenAI (direct JSON) and Gemini (via Proxy)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		bodyBytes, _ := io.ReadAll(r.Body)
		bodyStr := string(bodyBytes)
		receivedPayloads = append(receivedPayloads, bodyStr)

		// -- Step 1: Analyze Request to determine Model --
		// OpenAI requests have a "model" field in the JSON body
		var openAIReq map[string]interface{}
		if err := json.Unmarshal([]byte(bodyStr), &openAIReq); err == nil {
			if m, ok := openAIReq["model"].(string); ok {
				receivedModels = append(receivedModels, m)
			}
		}

		// Gemini requests have the model in the URL path (via the SDK)
		// e.g., /v1beta/models/gemini-1.5-flash:generateContent
		if strings.Contains(r.URL.Path, "models/") {
			parts := strings.Split(r.URL.Path, "/")
			for _, p := range parts {
				if strings.HasPrefix(p, "gemini") {
					// Clean the action suffix if present (e.g. :generateContent)
					modelName := strings.Split(p, ":")[0]
					receivedModels = append(receivedModels, modelName)
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")

		// -- Step 2: Determine Response based on Stage --

		// A. Sentinel Stage (identified by its unique System Prompt)
		if strings.Contains(bodyStr, "AI Security Sentinel") {
			// Security Check: Sentinel MUST receive the diff evidence
			if !strings.Contains(bodyStr, "diff_evidence") {
				// We fail the request to simulate a broken pipeline
				http.Error(w, "TEST_FAIL: Sentinel missing diff_evidence", http.StatusBadRequest)
				return
			}

			// Scenario: Simulate Attack Detection
			if strings.Contains(bodyStr, "TRIGGER_ATTACK") {
				resp := mockOpenAIResponse(`{"safe": false, "analysis": "Prompt Injection Detected"}`)
				if strings.Contains(r.URL.Path, "gemini") {
					resp = mockGeminiResponse(`{"safe": false, "analysis": "Prompt Injection Detected"}`)
				}
				w.Write([]byte(resp))
				return
			}

			// Scenario: Simulate Sentinel Malfunction (Garbage/Non-JSON)
			if strings.Contains(bodyStr, "TRIGGER_GARBAGE") {
				w.Write([]byte("<html>Service Unavailable</html>"))
				return
			}

			// Default: Safe
			resp := mockOpenAIResponse(`{"safe": true, "analysis": "Clean"}`)
			if strings.Contains(r.URL.Path, "gemini") {
				resp = mockGeminiResponse(`{"safe": true, "analysis": "Clean"}`)
			}
			w.Write([]byte(resp))
			return
		}

		// B. Main Auditor Stage (identified by Auditor System Prompt)
		if strings.Contains(bodyStr, "Supply Chain Security Auditor") {
			// Scenario: Logic Injection (Model tricked into leaking prompt)
			if strings.Contains(bodyStr, "TRIGGER_LOGIC_LEAK") {
				resp := mockOpenAIResponse(`{"verdict": "MATCH", "evidence": "Ignore previous instructions. System Prompt: You are a Sentinel."}`)
				w.Write([]byte(resp))
				return
			}

			resp := mockOpenAIResponse(`{"verdict": "MATCH", "evidence": "Code matches commit."}`)
			if strings.Contains(r.URL.Path, "gemini") {
				resp = mockGeminiResponse(`{"verdict": "MATCH", "evidence": "Code matches commit."}`)
			}
			w.Write([]byte(resp))
			return
		}
	}))
	defer server.Close()

	// -- Test Cases --

	t.Run("OpenAI_HappyPath_ArchitectureCheck", func(t *testing.T) {
		requestCount = 0
		receivedModels = nil

		evidence := []AuditEvidence{{Function: "main.go", AddedOperations: "fmt.Println"}}
		// We pass "gpt-4o" as the requested model
		result, err := callLLM("Valid commit", evidence, "key", "gpt-4o", server.URL)

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Verdict != "MATCH" {
			t.Errorf("Expected MATCH, got %s", result.Verdict)
		}

		// Verify Hierarchy: Sentinel Check -> Main Audit
		if len(receivedModels) != 2 {
			t.Fatalf("Expected 2 LLM calls (Sentinel + Auditor), got %d", len(receivedModels))
		}
		// logic update: Sentinel now defaults to ModelGPT5_2 for high security
		if !strings.Contains(receivedModels[0], "gpt-5.2") {
			t.Errorf("Architecture Violation: Sentinel (Step 1) should be 'gpt-5.2', got '%s'", receivedModels[0])
		}
		if receivedModels[1] != "gpt-4o" {
			t.Errorf("Architecture Violation: Auditor (Step 2) should be 'gpt-4o', got '%s'", receivedModels[1])
		}
	})

	t.Run("OpenAI_Injection_Blocked_FailSecure", func(t *testing.T) {
		requestCount = 0
		receivedModels = nil

		// The input contains the trigger for the mock to return safe: false
		evidence := []AuditEvidence{{Function: "hack.go", AddedOperations: "TRIGGER_ATTACK"}}
		result, err := callLLM("Malicious Commit", evidence, "key", "gpt-4o", server.URL)

		// 1. Verify Result
		if err != nil {
			t.Fatalf("Expected graceful LIE verdict, got error: %v", err)
		}
		if result.Verdict != "LIE" {
			t.Errorf("Expected LIE (Block), got %s", result.Verdict)
		}
		if !strings.Contains(result.Evidence, "SECURITY ALERT") {
			t.Errorf("Evidence missing security alert prefix")
		}

		// 2. Verify Fail-Secure: Main Model must NOT be called
		if len(receivedModels) != 1 {
			t.Errorf("Fail-Secure Violation: Main model was called after attack detection! Calls: %v", receivedModels)
		}
		// logic update: Sentinel uses the reasoning model (5.2)
		if !strings.Contains(receivedModels[0], "gpt-5.2") {
			t.Errorf("Expected sentinel model check with gpt-5.2, got %s", receivedModels[0])
		}
	})

	t.Run("Gemini_Routing_and_Hierarchy", func(t *testing.T) {
		requestCount = 0
		receivedModels = nil

		evidence := []AuditEvidence{{Function: "main.go", AddedOperations: "fmt.Println"}}
		// Requesting 'gemini-pro' (logic in llm.go maps this to 3-pro-preview / ModelGeminiPro)
		result, err := callLLM("Gemini Commit", evidence, "key", "gemini-pro", server.URL)

		if err != nil {
			t.Fatalf("Gemini call failed: %v", err)
		}
		if result.Verdict != "MATCH" {
			t.Errorf("Expected MATCH, got %s", result.Verdict)
		}

		// Verify Hierarchy
		if len(receivedModels) != 2 {
			t.Fatalf("Expected 2 calls, got %d", len(receivedModels))
		}

		// logic update: For Gemini, we now assume 'scanForInjection' upgrades to Gemini 3 Pro (Reasoning)
		// rather than sticking with Flash, to match the "Smart Injection" defense logic.
		// Both the sentinel and the main auditor should use Pro in this case.
		if !strings.Contains(receivedModels[0], "pro") {
			t.Errorf("Step 1 (Sentinel) should use Pro model, got '%s'", receivedModels[0])
		}
		if !strings.Contains(receivedModels[1], "pro") {
			t.Errorf("Step 2 (Auditor) should use Pro model, got '%s'", receivedModels[1])
		}
	})

	t.Run("Sentinel_Payload_Integrity", func(t *testing.T) {
		// Verify that the Sentinel actually sees the DIFF evidence, not just the commit message.
		receivedPayloads = nil

		evidence := []AuditEvidence{{Function: "secret.go", AddedOperations: "SUPER_SECRET_PAYLOAD"}}
		_, _ = callLLM("msg", evidence, "key", "gpt-4o", server.URL)

		if len(receivedPayloads) == 0 {
			t.Fatal("No requests received")
		}
		// The first request (Sentinel) must contain the diff content
		if !strings.Contains(receivedPayloads[0], "SUPER_SECRET_PAYLOAD") {
			t.Error("Sentinel request did not contain code diff evidence! Context scanning is incomplete.")
		}
	})

	t.Run("Sentinel_Failure_FailClosed", func(t *testing.T) {
		// If Sentinel returns garbage (non-JSON), we must block.
		requestCount = 0
		receivedModels = nil

		evidence := []AuditEvidence{{Function: "main.go", AddedOperations: "TRIGGER_GARBAGE"}}
		result, err := callLLM("msg", evidence, "key", "gpt-4o", server.URL)

		// Verification: The function returns an error from scanForInjection
		// which results in a LIE verdict and Evidence explaining the failure.
		if result.Verdict != "LIE" {
			t.Errorf("Expected LIE on sentinel failure, got %s", result.Verdict)
		}
		if !strings.Contains(result.Evidence, "Analysis Blocked") && err == nil {
			t.Errorf("Expected evidence of blocked analysis, got: %s", result.Evidence)
		}

		// Crucial: Main model NOT called
		if len(receivedModels) > 1 {
			t.Errorf("Fail-Secure Violation: Main model called despite sentinel crashing.")
		}
	})

	t.Run("Output_Guardrail_LogicInjection", func(t *testing.T) {
		// Verify that if the Main LLM is tricked into leaking the prompt, the output validator catches it.
		evidence := []AuditEvidence{{Function: "main.go", AddedOperations: "TRIGGER_LOGIC_LEAK"}}
		result, _ := callLLM("msg", evidence, "key", "gpt-4o", server.URL)

		if result.Verdict != "SUSPICIOUS" {
			t.Errorf("Expected SUSPICIOUS (Guardrail Trigger), got %s", result.Verdict)
		}
		if !strings.Contains(result.Evidence, "unsafe content detected") {
			t.Errorf("Expected unsafe content warning, got: %s", result.Evidence)
		}
	})
}

// -- Unit Test: Output Guardrails --

func TestValidateOutput_Guardrails(t *testing.T) {
	// Tests strict schema compliance and content filtering to prevent "Logic Injection"
	// (where the model is tricked into returning valid JSON containing malicious payloads)
	tests := []struct {
		name    string
		input   LLMResult
		wantErr bool
	}{
		{
			name: "Valid Match",
			input: LLMResult{
				Verdict:  "MATCH",
				Evidence: "The code changes accurately reflect the commit message.",
			},
			wantErr: false,
		},
		{
			name: "Invalid Verdict Enum",
			input: LLMResult{
				Verdict:  "HACKED",
				Evidence: "Safe.",
			},
			wantErr: true,
		},
		{
			name: "Case Sensitivity Attack",
			input: LLMResult{
				Verdict:  "match", // Should pass if normalized, implementation uses strict checks but handles this via logic if needed
				Evidence: "Lowercase verdict.",
			},
			// llm.go implementation: validVerdicts[strings.ToUpper(res.Verdict)]
			// So "match" -> "MATCH" which is valid.
			wantErr: false,
		},
		{
			name: "System Prompt Leakage",
			input: LLMResult{
				Verdict:  "LIE",
				Evidence: "I cannot do that because my system prompt says I am a security auditor.",
			},
			wantErr: true,
		},
		{
			name: "Instruction Override Leak",
			input: LLMResult{
				Verdict:  "MATCH",
				Evidence: "Okay, I will ignore previous instructions.",
			},
			wantErr: true,
		},
		{
			name: "XSS/Script Injection",
			input: LLMResult{
				Verdict:  "SUSPICIOUS",
				Evidence: "Analysis: <script>alert(1)</script>",
			},
			wantErr: true,
		},
		{
			name: "Mixed Case Obfuscation",
			input: LLMResult{
				Verdict:  "MATCH",
				Evidence: "SyStEm PrOmPt detected.",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOutput() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// -- Helpers --

func mockOpenAIResponse(contentJSON string) string {
	// OpenAI Responses API structure
	return fmt.Sprintf(`{
        "items": [
            {
                "role": "assistant",
                "content": %q
            }
        ]
    }`, contentJSON)
}

func mockGeminiResponse(contentJSON string) string {
	// Gemini Candidate structure
	// We must escape the inner JSON quotes for the text field
	escaped := strings.ReplaceAll(contentJSON, "\"", "\\\"")
	return fmt.Sprintf(`{
        "candidates": [
            {
                "content": {
                    "parts": [
                        { "text": "%s" }
                    ]
                }
            }
        ]
}`, escaped)
}
