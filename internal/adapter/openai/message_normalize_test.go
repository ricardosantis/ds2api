package openai

import (
	"strings"
	"testing"

	"ds2api/internal/util"
)

func TestNormalizeOpenAIMessagesForPrompt_AssistantToolCallsAndToolResult(t *testing.T) {
	raw := []any{
		map[string]any{"role": "system", "content": "You are helpful"},
		map[string]any{"role": "user", "content": "查北京天气"},
		map[string]any{
			"role":    "assistant",
			"content": nil,
			"tool_calls": []any{
				map[string]any{
					"id":   "call_1",
					"type": "function",
					"function": map[string]any{
						"name":      "get_weather",
						"arguments": "{\"city\":\"beijing\"}",
					},
				},
			},
		},
		map[string]any{
			"role":         "tool",
			"tool_call_id": "call_1",
			"name":         "get_weather",
			"content":      "{\"temp\":18}",
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	if len(normalized) != 3 {
		t.Fatalf("expected 3 normalized messages, got %d", len(normalized))
	}
	toolContent, _ := normalized[2]["content"].(string)
	if !strings.Contains(toolContent, `"temp":18`) {
		t.Fatalf("tool result should be transparently forwarded, got %q", toolContent)
	}
	if strings.Contains(toolContent, "[TOOL_RESULT_HISTORY]") {
		t.Fatalf("tool history marker should not be injected: %q", toolContent)
	}

	prompt := util.MessagesPrepare(normalized)
	if strings.Contains(prompt, "[TOOL_CALL_HISTORY]") || strings.Contains(prompt, "[TOOL_RESULT_HISTORY]") {
		t.Fatalf("expected no synthetic history markers in prompt: %q", prompt)
	}
}

func TestNormalizeOpenAIMessagesForPrompt_ToolObjectContentPreserved(t *testing.T) {
	raw := []any{
		map[string]any{
			"role":         "tool",
			"tool_call_id": "call_2",
			"name":         "get_weather",
			"content": map[string]any{
				"temp":      18,
				"condition": "sunny",
			},
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	got, _ := normalized[0]["content"].(string)
	if !strings.Contains(got, `"temp":18`) || !strings.Contains(got, `"condition":"sunny"`) {
		t.Fatalf("expected serialized object in tool content, got %q", got)
	}
}

func TestNormalizeOpenAIMessagesForPrompt_ToolArrayBlocksJoined(t *testing.T) {
	raw := []any{
		map[string]any{
			"role":         "tool",
			"tool_call_id": "call_3",
			"name":         "read_file",
			"content": []any{
				map[string]any{"type": "input_text", "text": "line-1"},
				map[string]any{"type": "output_text", "text": "line-2"},
				map[string]any{"type": "image_url", "image_url": "https://example.com/a.png"},
			},
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	got, _ := normalized[0]["content"].(string)
	if !strings.Contains(got, "line-1\nline-2") {
		t.Fatalf("expected joined text blocks, got %q", got)
	}
}

func TestNormalizeOpenAIMessagesForPrompt_FunctionRoleCompatible(t *testing.T) {
	raw := []any{
		map[string]any{
			"role":         "function",
			"tool_call_id": "call_4",
			"name":         "legacy_tool",
			"content": map[string]any{
				"ok": true,
			},
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	if len(normalized) != 1 {
		t.Fatalf("expected one normalized message, got %d", len(normalized))
	}
	if normalized[0]["role"] != "user" {
		t.Fatalf("expected function role mapped to user, got %#v", normalized[0]["role"])
	}
	got, _ := normalized[0]["content"].(string)
	if strings.Contains(got, "name: legacy_tool") || !strings.Contains(got, `"ok":true`) {
		t.Fatalf("unexpected normalized function-role content: %q", got)
	}
}

func TestNormalizeOpenAIMessagesForPrompt_AssistantMultipleToolCallsRemainSeparated(t *testing.T) {
	raw := []any{
		map[string]any{
			"role": "assistant",
			"tool_calls": []any{
				map[string]any{
					"id":   "call_search",
					"type": "function",
					"function": map[string]any{
						"name":      "search_web",
						"arguments": `{"query":"latest ai news"}`,
					},
				},
				map[string]any{
					"id":   "call_eval",
					"type": "function",
					"function": map[string]any{
						"name":      "eval_javascript",
						"arguments": `{"code":"1+1"}`,
					},
				},
			},
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	if len(normalized) != 0 {
		t.Fatalf("expected assistant tool_call-only message to be dropped in passthrough mode, got %#v", normalized)
	}
}

func TestNormalizeOpenAIMessagesForPrompt_PreservesConcatenatedToolArguments(t *testing.T) {
	raw := []any{
		map[string]any{
			"role": "assistant",
			"tool_calls": []any{
				map[string]any{
					"id": "call_1",
					"function": map[string]any{
						"name":      "search_web",
						"arguments": `{}{"query":"测试工具调用"}`,
					},
				},
			},
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	if len(normalized) != 0 {
		t.Fatalf("expected no synthetic assistant message for tool_call-only content, got %#v", normalized)
	}
}

func TestNormalizeOpenAIMessagesForPrompt_AssistantToolCallsMissingNameAreDropped(t *testing.T) {
	raw := []any{
		map[string]any{
			"role": "assistant",
			"tool_calls": []any{
				map[string]any{
					"id":   "call_missing_name",
					"type": "function",
					"function": map[string]any{
						"arguments": `{"path":"README.MD"}`,
					},
				},
			},
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	if len(normalized) != 0 {
		t.Fatalf("expected nameless assistant tool_calls to be dropped, got %#v", normalized)
	}
}

func TestNormalizeOpenAIMessagesForPrompt_AssistantNilContentDoesNotInjectNullLiteral(t *testing.T) {
	raw := []any{
		map[string]any{
			"role":    "assistant",
			"content": nil,
			"tool_calls": []any{
				map[string]any{
					"id": "call_screenshot",
					"function": map[string]any{
						"name":      "send_file_to_user",
						"arguments": `{"file_path":"/tmp/a.png"}`,
					},
				},
			},
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	if len(normalized) != 0 {
		t.Fatalf("expected nil-content assistant tool_call-only message to be dropped, got %#v", normalized)
	}
}

func TestNormalizeOpenAIMessagesForPrompt_DeveloperRoleMapsToSystem(t *testing.T) {
	raw := []any{
		map[string]any{"role": "developer", "content": "必须先走工具调用"},
		map[string]any{"role": "user", "content": "你好"},
	}
	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	if len(normalized) != 2 {
		t.Fatalf("expected 2 normalized messages, got %d", len(normalized))
	}
	if normalized[0]["role"] != "system" {
		t.Fatalf("expected developer role converted to system, got %#v", normalized[0]["role"])
	}
}

func TestNormalizeOpenAIMessagesForPrompt_AssistantArrayContentFallbackWhenTextEmpty(t *testing.T) {
	raw := []any{
		map[string]any{
			"role": "assistant",
			"content": []any{
				map[string]any{"type": "text", "text": "", "content": "工具说明文本"},
			},
		},
	}

	normalized := normalizeOpenAIMessagesForPrompt(raw, "")
	if len(normalized) != 1 {
		t.Fatalf("expected one normalized message, got %d", len(normalized))
	}
	content, _ := normalized[0]["content"].(string)
	if content != "工具说明文本" {
		t.Fatalf("expected content fallback text preserved, got %q", content)
	}
}
