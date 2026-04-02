package claude

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type openAIProxyStub struct {
	status int
	body   string
}

func (s openAIProxyStub) ChatCompletions(w http.ResponseWriter, _ *http.Request) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s.status)
	_, _ = w.Write([]byte(s.body))
}

func TestClaudeProxyViaOpenAIVercelPreparePassthrough(t *testing.T) {
	h := &Handler{OpenAI: openAIProxyStub{status: 200, body: `{"lease_id":"lease_123","payload":{"a":1}}`}}
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages?__stream_prepare=1", strings.NewReader(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	rec := httptest.NewRecorder()

	h.Messages(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("expected json response, got err=%v body=%s", err, rec.Body.String())
	}
	if _, ok := out["lease_id"]; !ok {
		t.Fatalf("expected lease_id in prepare passthrough, got=%v", out)
	}
}
