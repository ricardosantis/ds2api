package translatorcliproxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

func TestOpenAIStreamTranslatorWriterClaude(t *testing.T) {
	original := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	translated := []byte(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}],"stream":true}`)

	rec := httptest.NewRecorder()
	w := NewOpenAIStreamTranslatorWriter(rec, sdktranslator.FormatClaude, "claude-sonnet-4-5", original, translated)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl_1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"claude-sonnet-4-5\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n"))
	_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl_1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"claude-sonnet-4-5\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n"))
	_, _ = w.Write([]byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	if !strings.Contains(body, "event: message_start") {
		t.Fatalf("expected claude message_start event, got: %s", body)
	}
}

func TestOpenAIStreamTranslatorWriterGemini(t *testing.T) {
	original := []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`)
	translated := []byte(`{"model":"gemini-2.5-pro","messages":[{"role":"user","content":"hi"}],"stream":true}`)

	rec := httptest.NewRecorder()
	w := NewOpenAIStreamTranslatorWriter(rec, sdktranslator.FormatGemini, "gemini-2.5-pro", original, translated)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl_1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gemini-2.5-pro\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n"))
	_, _ = w.Write([]byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	if !strings.Contains(body, "candidates") {
		t.Fatalf("expected gemini stream payload, got: %s", body)
	}
}
