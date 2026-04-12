package prompt

import (
	"strings"
	"testing"
)

func TestNormalizeContentNilReturnsEmpty(t *testing.T) {
	if got := NormalizeContent(nil); got != "" {
		t.Fatalf("expected empty string for nil content, got %q", got)
	}
}

func TestMessagesPrepareNilContentNoNullLiteral(t *testing.T) {
	messages := []map[string]any{
		{"role": "assistant", "content": nil},
		{"role": "user", "content": "ok"},
	}
	got := MessagesPrepare(messages)
	if got == "" {
		t.Fatalf("expected non-empty output")
	}
	if got == "null" {
		t.Fatalf("expected no null literal output, got %q", got)
	}
}

func TestMessagesPrepareUsesTurnSuffixes(t *testing.T) {
	messages := []map[string]any{
		{"role": "system", "content": "System rule"},
		{"role": "user", "content": "Question"},
		{"role": "assistant", "content": "Answer"},
	}
	got := MessagesPrepare(messages)
	if !strings.HasPrefix(got, "<｜begin▁of▁sentence｜>") {
		t.Fatalf("expected begin-of-sentence marker, got %q", got)
	}
	if !strings.Contains(got, "<｜System｜>\nSystem rule<｜end▁of▁instructions｜>") {
		t.Fatalf("expected system instructions suffix, got %q", got)
	}
	if !strings.Contains(got, "<｜User｜>\nQuestion<｜end▁of▁sentence｜>") {
		t.Fatalf("expected user sentence suffix, got %q", got)
	}
	if !strings.Contains(got, "<｜Assistant｜>\n</think>Answer<｜end▁of▁sentence｜>") {
		t.Fatalf("expected assistant sentence suffix, got %q", got)
	}
}

func TestNormalizeContentArrayFallsBackToContentWhenTextEmpty(t *testing.T) {
	got := NormalizeContent([]any{
		map[string]any{"type": "text", "text": "", "content": "from-content"},
	})
	if got != "from-content" {
		t.Fatalf("expected fallback to content when text is empty, got %q", got)
	}
}

func TestMessagesPrepareWithThinkingEndsWithOpenThink(t *testing.T) {
	messages := []map[string]any{{"role": "user", "content": "Question"}}
	got := MessagesPrepareWithThinking(messages, true)
	if !strings.HasSuffix(got, "<｜Assistant｜><think>") {
		t.Fatalf("expected thinking suffix, got %q", got)
	}
}
