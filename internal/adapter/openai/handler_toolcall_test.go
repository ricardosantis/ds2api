package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func makeSSEHTTPResponse(lines ...string) *http.Response {
	body := strings.Join(lines, "\n")
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func decodeJSONBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode json failed: %v, body=%s", err, body)
	}
	return out
}

func parseSSEDataFrames(t *testing.T, body string) ([]map[string]any, bool) {
	t.Helper()
	lines := strings.Split(body, "\n")
	frames := make([]map[string]any, 0, len(lines))
	done := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			continue
		}
		if payload == "[DONE]" {
			done = true
			continue
		}
		var frame map[string]any
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			t.Fatalf("decode sse frame failed: %v, payload=%s", err, payload)
		}
		frames = append(frames, frame)
	}
	return frames, done
}

func streamHasRawToolJSONContent(frames []map[string]any) bool {
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			content, _ := delta["content"].(string)
			if strings.Contains(content, `"tool_calls"`) {
				return true
			}
		}
	}
	return false
}

func streamHasToolCallsDelta(frames []map[string]any) bool {
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			if _, ok := delta["tool_calls"]; ok {
				return true
			}
		}
	}
	return false
}

func streamFinishReason(frames []map[string]any) string {
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			if reason, ok := choice["finish_reason"].(string); ok && reason != "" {
				return reason
			}
		}
	}
	return ""
}

func TestHandleNonStreamToolCallInterceptsChatModel(t *testing.T) {
	h := &Handler{}
	resp := makeSSEHTTPResponse(
		`data: {"p":"response/content","v":"{\"tool_calls\":[{\"name\":\"search\",\"input\":{\"q\":\"go\"}}]}"}`,
		`data: [DONE]`,
	)
	rec := httptest.NewRecorder()

	h.handleNonStream(rec, context.Background(), resp, "cid1", "deepseek-chat", "prompt", false, false, []string{"search"})
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}

	out := decodeJSONBody(t, rec.Body.String())
	choices, _ := out["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("unexpected choices: %#v", out["choices"])
	}
	choice, _ := choices[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Fatalf("expected finish_reason=tool_calls, got %#v", choice["finish_reason"])
	}
	msg, _ := choice["message"].(map[string]any)
	if msg["content"] != nil {
		t.Fatalf("expected content nil, got %#v", msg["content"])
	}
	toolCalls, _ := msg["tool_calls"].([]any)
	if len(toolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %#v", msg["tool_calls"])
	}
}

func TestHandleNonStreamToolCallInterceptsReasonerModel(t *testing.T) {
	h := &Handler{}
	resp := makeSSEHTTPResponse(
		`data: {"p":"response/thinking_content","v":"先想一下"}`,
		`data: {"p":"response/content","v":"{\"tool_calls\":[{\"name\":\"search\",\"input\":{\"q\":\"go\"}}]}"}`,
		`data: [DONE]`,
	)
	rec := httptest.NewRecorder()

	h.handleNonStream(rec, context.Background(), resp, "cid2", "deepseek-reasoner", "prompt", true, false, []string{"search"})
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}

	out := decodeJSONBody(t, rec.Body.String())
	choices, _ := out["choices"].([]any)
	choice, _ := choices[0].(map[string]any)
	msg, _ := choice["message"].(map[string]any)
	if msg["reasoning_content"] != "先想一下" {
		t.Fatalf("expected reasoning_content, got %#v", msg["reasoning_content"])
	}
	if msg["content"] != nil {
		t.Fatalf("expected content nil, got %#v", msg["content"])
	}
	if choice["finish_reason"] != "tool_calls" {
		t.Fatalf("expected finish_reason=tool_calls, got %#v", choice["finish_reason"])
	}
}

func TestHandleNonStreamUnknownToolStillIntercepted(t *testing.T) {
	h := &Handler{}
	resp := makeSSEHTTPResponse(
		`data: {"p":"response/content","v":"{\"tool_calls\":[{\"name\":\"not_in_schema\",\"input\":{\"q\":\"go\"}}]}"}`,
		`data: [DONE]`,
	)
	rec := httptest.NewRecorder()

	h.handleNonStream(rec, context.Background(), resp, "cid2b", "deepseek-chat", "prompt", false, false, []string{"search"})
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}

	out := decodeJSONBody(t, rec.Body.String())
	choices, _ := out["choices"].([]any)
	choice, _ := choices[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Fatalf("expected finish_reason=tool_calls, got %#v", choice["finish_reason"])
	}
	msg, _ := choice["message"].(map[string]any)
	if msg["content"] != nil {
		t.Fatalf("expected content nil, got %#v", msg["content"])
	}
	toolCalls, _ := msg["tool_calls"].([]any)
	if len(toolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %#v", msg["tool_calls"])
	}
}

func TestHandleStreamToolCallInterceptsWithoutRawContentLeak(t *testing.T) {
	h := &Handler{}
	resp := makeSSEHTTPResponse(
		`data: {"p":"response/content","v":"{\"tool_calls\":[{\"name\":\"search\""}`,
		`data: {"p":"response/content","v":",\"input\":{\"q\":\"go\"}}]}"}`,
		`data: [DONE]`,
	)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	h.handleStream(rec, req, resp, "cid3", "deepseek-chat", "prompt", false, false, []string{"search"})

	frames, done := parseSSEDataFrames(t, rec.Body.String())
	if !done {
		t.Fatalf("expected [DONE], body=%s", rec.Body.String())
	}
	if !streamHasToolCallsDelta(frames) {
		t.Fatalf("expected tool_calls delta, body=%s", rec.Body.String())
	}
	foundToolIndex := false
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			toolCalls, _ := delta["tool_calls"].([]any)
			for _, tc := range toolCalls {
				tcm, _ := tc.(map[string]any)
				if _, ok := tcm["index"].(float64); ok {
					foundToolIndex = true
				}
			}
		}
	}
	if !foundToolIndex {
		t.Fatalf("expected stream tool_calls item with index, body=%s", rec.Body.String())
	}
	if streamHasRawToolJSONContent(frames) {
		t.Fatalf("raw tool_calls JSON leaked in content delta: %s", rec.Body.String())
	}
	if streamFinishReason(frames) != "tool_calls" {
		t.Fatalf("expected finish_reason=tool_calls, body=%s", rec.Body.String())
	}
}

func TestHandleStreamReasonerToolCallInterceptsWithoutRawContentLeak(t *testing.T) {
	h := &Handler{}
	resp := makeSSEHTTPResponse(
		`data: {"p":"response/thinking_content","v":"思考中"}`,
		`data: {"p":"response/content","v":"{\"tool_calls\":[{\"name\":\"search\",\"input\":{\"q\":\"go\"}}]}"}`,
		`data: [DONE]`,
	)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	h.handleStream(rec, req, resp, "cid4", "deepseek-reasoner", "prompt", true, false, []string{"search"})

	frames, done := parseSSEDataFrames(t, rec.Body.String())
	if !done {
		t.Fatalf("expected [DONE], body=%s", rec.Body.String())
	}
	if !streamHasToolCallsDelta(frames) {
		t.Fatalf("expected tool_calls delta, body=%s", rec.Body.String())
	}
	foundToolIndex := false
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			toolCalls, _ := delta["tool_calls"].([]any)
			for _, tc := range toolCalls {
				tcm, _ := tc.(map[string]any)
				if _, ok := tcm["index"].(float64); ok {
					foundToolIndex = true
				}
			}
		}
	}
	if !foundToolIndex {
		t.Fatalf("expected stream tool_calls item with index, body=%s", rec.Body.String())
	}
	if streamHasRawToolJSONContent(frames) {
		t.Fatalf("raw tool_calls JSON leaked in content delta: %s", rec.Body.String())
	}
	if streamFinishReason(frames) != "tool_calls" {
		t.Fatalf("expected finish_reason=tool_calls, body=%s", rec.Body.String())
	}

	hasThinkingDelta := false
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			if _, ok := delta["reasoning_content"]; ok {
				hasThinkingDelta = true
			}
		}
	}
	if !hasThinkingDelta {
		t.Fatalf("expected reasoning_content delta in reasoner stream: %s", rec.Body.String())
	}
}

func TestHandleStreamUnknownToolStillIntercepted(t *testing.T) {
	h := &Handler{}
	resp := makeSSEHTTPResponse(
		`data: {"p":"response/content","v":"{\"tool_calls\":[{\"name\":\"not_in_schema\",\"input\":{\"q\":\"go\"}}]}"}`,
		`data: [DONE]`,
	)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	h.handleStream(rec, req, resp, "cid5", "deepseek-chat", "prompt", false, false, []string{"search"})

	frames, done := parseSSEDataFrames(t, rec.Body.String())
	if !done {
		t.Fatalf("expected [DONE], body=%s", rec.Body.String())
	}
	if !streamHasToolCallsDelta(frames) {
		t.Fatalf("expected tool_calls delta, body=%s", rec.Body.String())
	}
	foundToolIndex := false
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			toolCalls, _ := delta["tool_calls"].([]any)
			for _, tc := range toolCalls {
				tcm, _ := tc.(map[string]any)
				if _, ok := tcm["index"].(float64); ok {
					foundToolIndex = true
				}
			}
		}
	}
	if !foundToolIndex {
		t.Fatalf("expected stream tool_calls item with index, body=%s", rec.Body.String())
	}
	if streamHasRawToolJSONContent(frames) {
		t.Fatalf("raw tool_calls JSON leaked in content delta: %s", rec.Body.String())
	}
}

func TestHandleStreamToolsPlainTextStreamsBeforeFinish(t *testing.T) {
	h := &Handler{}
	resp := makeSSEHTTPResponse(
		`data: {"p":"response/content","v":"你好，"}`,
		`data: {"p":"response/content","v":"这是普通文本回复。"}`,
		`data: [DONE]`,
	)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	h.handleStream(rec, req, resp, "cid6", "deepseek-chat", "prompt", false, false, []string{"search"})

	frames, done := parseSSEDataFrames(t, rec.Body.String())
	if !done {
		t.Fatalf("expected [DONE], body=%s", rec.Body.String())
	}
	if streamHasToolCallsDelta(frames) {
		t.Fatalf("did not expect tool_calls delta for plain text: %s", rec.Body.String())
	}
	content := strings.Builder{}
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			if c, ok := delta["content"].(string); ok {
				content.WriteString(c)
			}
		}
	}
	if got := content.String(); got == "" {
		t.Fatalf("expected streamed content in tool mode plain text, body=%s", rec.Body.String())
	}
	if streamFinishReason(frames) != "stop" {
		t.Fatalf("expected finish_reason=stop, body=%s", rec.Body.String())
	}
}

func TestHandleStreamToolCallMixedWithPlainTextSegments(t *testing.T) {
	h := &Handler{}
	resp := makeSSEHTTPResponse(
		`data: {"p":"response/content","v":"前置正文A。"}`,
		`data: {"p":"response/content","v":"{\"tool_calls\":[{\"name\":\"search\",\"input\":{\"q\":\"go\"}}]}"}`,
		`data: {"p":"response/content","v":"后置正文B。"}`,
		`data: [DONE]`,
	)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	h.handleStream(rec, req, resp, "cid7", "deepseek-chat", "prompt", false, false, []string{"search"})

	frames, done := parseSSEDataFrames(t, rec.Body.String())
	if !done {
		t.Fatalf("expected [DONE], body=%s", rec.Body.String())
	}
	if !streamHasToolCallsDelta(frames) {
		t.Fatalf("expected tool_calls delta in mixed stream, body=%s", rec.Body.String())
	}
	if streamHasRawToolJSONContent(frames) {
		t.Fatalf("raw tool_calls JSON leaked in mixed stream: %s", rec.Body.String())
	}
	content := strings.Builder{}
	for _, frame := range frames {
		choices, _ := frame["choices"].([]any)
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			if c, ok := delta["content"].(string); ok {
				content.WriteString(c)
			}
		}
	}
	got := content.String()
	if !strings.Contains(got, "前置正文A。") || !strings.Contains(got, "后置正文B。") {
		t.Fatalf("expected pre/post plain text to pass sieve, got=%q", got)
	}
	if streamFinishReason(frames) != "tool_calls" {
		t.Fatalf("expected finish_reason=tool_calls, body=%s", rec.Body.String())
	}
}
