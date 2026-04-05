package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"ds2api/internal/config"
	"ds2api/internal/devcapture"
	"ds2api/internal/rawsample"
)

func (h *Handler) captureRawSample(w http.ResponseWriter, r *http.Request) {
	if h.OpenAI == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"detail": "OpenAI handler is not configured"})
		return
	}

	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "invalid json"})
		return
	}

	payload, sampleID, apiKey, err := prepareRawSampleCaptureRequest(h.Store, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": err.Error()})
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"detail": "failed to encode capture request"})
		return
	}

	traceID := rawsample.NormalizeSampleID(sampleID)
	if traceID == "" {
		traceID = rawsample.DefaultSampleID("capture")
	}

	before := devcapture.Global().Snapshot()
	rec := httptest.NewRecorder()
	captureReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions?__trace_id="+url.QueryEscape(traceID), bytes.NewReader(body))
	captureReq.Header.Set("Authorization", "Bearer "+apiKey)
	captureReq.Header.Set("Content-Type", "application/json")
	h.OpenAI.ChatCompletions(rec, captureReq)
	after := devcapture.Global().Snapshot()

	if rec.Code >= http.StatusBadRequest {
		copyHeader(w.Header(), rec.Header())
		w.WriteHeader(rec.Code)
		_, _ = io.Copy(w, bytes.NewReader(rec.Body.Bytes()))
		return
	}

	captureEntries, err := collectNewCaptureEntries(before, after)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"detail": err.Error()})
		return
	}

	saved, err := rawsample.Persist(rawsample.PersistOptions{
		RootDir:      config.RawStreamSampleRoot(),
		SampleID:     sampleID,
		Source:       "admin/dev/raw-samples/capture",
		Request:      payload,
		Capture:      captureSummaryFromEntries(captureEntries),
		UpstreamBody: combineCaptureBodies(captureEntries),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"detail": err.Error()})
		return
	}

	copyHeader(w.Header(), rec.Header())
	w.Header().Set("X-Ds2-Sample-Id", saved.SampleID)
	w.Header().Set("X-Ds2-Sample-Dir", saved.Dir)
	w.Header().Set("X-Ds2-Sample-Meta", saved.MetaPath)
	w.Header().Set("X-Ds2-Sample-Upstream", saved.UpstreamPath)
	w.WriteHeader(rec.Code)
	_, _ = io.Copy(w, bytes.NewReader(rec.Body.Bytes()))
}

func prepareRawSampleCaptureRequest(store ConfigStore, req map[string]any) (map[string]any, string, string, error) {
	payload := cloneMap(req)
	sampleID := strings.TrimSpace(fieldString(payload, "sample_id"))
	apiKey := strings.TrimSpace(fieldString(payload, "api_key"))

	for _, k := range []string{"sample_id", "api_key", "promote_default", "persist", "source"} {
		delete(payload, k)
	}

	if apiKey == "" {
		if store == nil {
			return nil, "", "", fmt.Errorf("no api key provided")
		}
		keys := store.Keys()
		if len(keys) == 0 {
			return nil, "", "", fmt.Errorf("no api key available")
		}
		apiKey = strings.TrimSpace(keys[0])
	}

	if model := strings.TrimSpace(fieldString(payload, "model")); model == "" {
		payload["model"] = "deepseek-chat"
	}
	if _, ok := payload["stream"]; !ok {
		payload["stream"] = true
	}

	if messagesRaw, ok := payload["messages"].([]any); !ok || len(messagesRaw) == 0 {
		message := strings.TrimSpace(fieldString(payload, "message"))
		if message == "" {
			message = "你好"
		}
		payload["messages"] = []map[string]any{{"role": "user", "content": message}}
	}
	delete(payload, "message")

	if sampleID == "" {
		model := strings.TrimSpace(fieldString(payload, "model"))
		if model == "" {
			model = "capture"
		}
		sampleID = rawsample.DefaultSampleID(model)
	}

	return payload, sampleID, apiKey, nil
}

func collectNewCaptureEntries(before, after []devcapture.Entry) ([]devcapture.Entry, error) {
	beforeIDs := make(map[string]struct{}, len(before))
	for _, entry := range before {
		beforeIDs[entry.ID] = struct{}{}
	}

	entries := make([]devcapture.Entry, 0, len(after))
	for _, entry := range after {
		if _, ok := beforeIDs[entry.ID]; ok {
			continue
		}
		if strings.TrimSpace(entry.ResponseBody) == "" {
			continue
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no upstream capture was recorded")
	}

	// Snapshot order is newest-first; reverse to preserve the actual request order.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries, nil
}

func captureSummaryFromEntries(entries []devcapture.Entry) rawsample.CaptureSummary {
	if len(entries) == 0 {
		return rawsample.CaptureSummary{}
	}

	// Primary metadata comes from the first (initial) capture.
	summary := rawsample.CaptureSummary{
		Label:      strings.TrimSpace(entries[0].Label),
		URL:        strings.TrimSpace(entries[0].URL),
		StatusCode: entries[0].StatusCode,
	}

	// Record every round (initial + continuations) so replay/debug
	// can reconstruct the full multi-round interaction.
	totalBytes := 0
	rounds := make([]rawsample.CaptureRound, 0, len(entries))
	for _, entry := range entries {
		n := len(entry.ResponseBody)
		totalBytes += n
		rounds = append(rounds, rawsample.CaptureRound{
			Label:         strings.TrimSpace(entry.Label),
			URL:           strings.TrimSpace(entry.URL),
			StatusCode:    entry.StatusCode,
			ResponseBytes: n,
		})
	}
	summary.ResponseBytes = totalBytes
	if len(rounds) > 1 {
		summary.Rounds = rounds
	}
	return summary
}

func combineCaptureBodies(entries []devcapture.Entry) []byte {
	if len(entries) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, entry := range entries {
		if buf.Len() > 0 {
			last := buf.Bytes()[buf.Len()-1]
			if last != '\n' {
				buf.WriteByte('\n')
			}
		}
		buf.WriteString(entry.ResponseBody)
	}
	return buf.Bytes()
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		dst.Del(k)
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
