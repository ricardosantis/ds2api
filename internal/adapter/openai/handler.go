package openai

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"ds2api/internal/auth"
	"ds2api/internal/config"
	"ds2api/internal/deepseek"
	"ds2api/internal/sse"
	"ds2api/internal/util"
)

type Handler struct {
	Store *config.Store
	Auth  *auth.Resolver
	DS    *deepseek.Client

	leaseMu      sync.Mutex
	streamLeases map[string]streamLease
}

type streamLease struct {
	Auth      *auth.RequestAuth
	ExpiresAt time.Time
}

type toolStreamSieveState struct {
	pending   strings.Builder
	capture   strings.Builder
	capturing bool
}

type toolStreamEvent struct {
	Content   string
	ToolCalls []util.ParsedToolCall
}

func RegisterRoutes(r chi.Router, h *Handler) {
	r.Get("/v1/models", h.ListModels)
	r.Post("/v1/chat/completions", h.ChatCompletions)
}

func (h *Handler) ListModels(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, config.OpenAIModelsResponse())
}

func (h *Handler) ChatCompletions(w http.ResponseWriter, r *http.Request) {
	if isVercelStreamReleaseRequest(r) {
		h.handleVercelStreamRelease(w, r)
		return
	}
	if isVercelStreamPrepareRequest(r) {
		h.handleVercelStreamPrepare(w, r)
		return
	}

	a, err := h.Auth.Determine(r)
	if err != nil {
		status := http.StatusUnauthorized
		detail := err.Error()
		if err == auth.ErrNoAccount {
			status = http.StatusTooManyRequests
		}
		writeOpenAIError(w, status, detail)
		return
	}
	defer h.Auth.Release(a)
	r = r.WithContext(auth.WithAuth(r.Context(), a))

	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid json")
		return
	}
	model, _ := req["model"].(string)
	messagesRaw, _ := req["messages"].([]any)
	if model == "" || len(messagesRaw) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "Request must include 'model' and 'messages'.")
		return
	}
	thinkingEnabled, searchEnabled, ok := config.GetModelConfig(model)
	if !ok {
		writeOpenAIError(w, http.StatusServiceUnavailable, fmt.Sprintf("Model '%s' is not available.", model))
		return
	}

	messages := normalizeMessages(messagesRaw)
	toolNames := []string{}
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		messages, toolNames = injectToolPrompt(messages, tools)
	}
	finalPrompt := util.MessagesPrepare(messages)

	sessionID, err := h.DS.CreateSession(r.Context(), a, 3)
	if err != nil {
		if a.UseConfigToken {
			writeOpenAIError(w, http.StatusUnauthorized, "Account token is invalid. Please re-login the account in admin.")
		} else {
			writeOpenAIError(w, http.StatusUnauthorized, "Invalid token. If this should be a DS2API key, add it to config.keys first.")
		}
		return
	}
	pow, err := h.DS.GetPow(r.Context(), a, 3)
	if err != nil {
		writeOpenAIError(w, http.StatusUnauthorized, "Failed to get PoW (invalid token or unknown error).")
		return
	}
	payload := map[string]any{
		"chat_session_id":   sessionID,
		"parent_message_id": nil,
		"prompt":            finalPrompt,
		"ref_file_ids":      []any{},
		"thinking_enabled":  thinkingEnabled,
		"search_enabled":    searchEnabled,
	}
	resp, err := h.DS.CallCompletion(r.Context(), a, payload, pow, 3)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "Failed to get completion.")
		return
	}
	if toBool(req["stream"]) {
		h.handleStream(w, r, resp, sessionID, model, finalPrompt, thinkingEnabled, searchEnabled, toolNames)
		return
	}
	h.handleNonStream(w, r.Context(), resp, sessionID, model, finalPrompt, thinkingEnabled, searchEnabled, toolNames)
}

func (h *Handler) handleVercelStreamPrepare(w http.ResponseWriter, r *http.Request) {
	if !config.IsVercel() {
		http.NotFound(w, r)
		return
	}
	h.sweepExpiredStreamLeases()
	internalSecret := vercelInternalSecret()
	internalToken := strings.TrimSpace(r.Header.Get("X-Ds2-Internal-Token"))
	if internalSecret == "" || subtle.ConstantTimeCompare([]byte(internalToken), []byte(internalSecret)) != 1 {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized internal request")
		return
	}

	a, err := h.Auth.Determine(r)
	if err != nil {
		status := http.StatusUnauthorized
		if err == auth.ErrNoAccount {
			status = http.StatusTooManyRequests
		}
		writeOpenAIError(w, status, err.Error())
		return
	}
	leased := false
	defer func() {
		if !leased {
			h.Auth.Release(a)
		}
	}()
	r = r.WithContext(auth.WithAuth(r.Context(), a))

	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !toBool(req["stream"]) {
		writeOpenAIError(w, http.StatusBadRequest, "stream must be true")
		return
	}
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		writeOpenAIError(w, http.StatusBadRequest, "tools are not supported by vercel stream prepare")
		return
	}

	model, _ := req["model"].(string)
	messagesRaw, _ := req["messages"].([]any)
	if model == "" || len(messagesRaw) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "Request must include 'model' and 'messages'.")
		return
	}
	thinkingEnabled, searchEnabled, ok := config.GetModelConfig(model)
	if !ok {
		writeOpenAIError(w, http.StatusServiceUnavailable, fmt.Sprintf("Model '%s' is not available.", model))
		return
	}

	messages := normalizeMessages(messagesRaw)
	finalPrompt := util.MessagesPrepare(messages)

	sessionID, err := h.DS.CreateSession(r.Context(), a, 3)
	if err != nil {
		if a.UseConfigToken {
			writeOpenAIError(w, http.StatusUnauthorized, "Account token is invalid. Please re-login the account in admin.")
		} else {
			writeOpenAIError(w, http.StatusUnauthorized, "Invalid token. If this should be a DS2API key, add it to config.keys first.")
		}
		return
	}
	powHeader, err := h.DS.GetPow(r.Context(), a, 3)
	if err != nil {
		writeOpenAIError(w, http.StatusUnauthorized, "Failed to get PoW (invalid token or unknown error).")
		return
	}
	if strings.TrimSpace(a.DeepSeekToken) == "" {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid token. If this should be a DS2API key, add it to config.keys first.")
		return
	}

	payload := map[string]any{
		"chat_session_id":   sessionID,
		"parent_message_id": nil,
		"prompt":            finalPrompt,
		"ref_file_ids":      []any{},
		"thinking_enabled":  thinkingEnabled,
		"search_enabled":    searchEnabled,
	}
	leaseID := h.holdStreamLease(a)
	if leaseID == "" {
		writeOpenAIError(w, http.StatusInternalServerError, "failed to create stream lease")
		return
	}
	leased = true
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":       sessionID,
		"lease_id":         leaseID,
		"model":            model,
		"final_prompt":     finalPrompt,
		"thinking_enabled": thinkingEnabled,
		"search_enabled":   searchEnabled,
		"deepseek_token":   a.DeepSeekToken,
		"pow_header":       powHeader,
		"payload":          payload,
	})
}

func (h *Handler) handleVercelStreamRelease(w http.ResponseWriter, r *http.Request) {
	if !config.IsVercel() {
		http.NotFound(w, r)
		return
	}
	h.sweepExpiredStreamLeases()
	internalSecret := vercelInternalSecret()
	internalToken := strings.TrimSpace(r.Header.Get("X-Ds2-Internal-Token"))
	if internalSecret == "" || subtle.ConstantTimeCompare([]byte(internalToken), []byte(internalSecret)) != 1 {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized internal request")
		return
	}

	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid json")
		return
	}
	leaseID, _ := req["lease_id"].(string)
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "lease_id is required")
		return
	}
	if !h.releaseStreamLease(leaseID) {
		writeOpenAIError(w, http.StatusNotFound, "stream lease not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (h *Handler) handleNonStream(w http.ResponseWriter, ctx context.Context, resp *http.Response, completionID, model, finalPrompt string, thinkingEnabled, searchEnabled bool, toolNames []string) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		writeOpenAIError(w, resp.StatusCode, string(body))
		return
	}
	thinking := strings.Builder{}
	text := strings.Builder{}
	currentType := "text"
	if thinkingEnabled {
		currentType = "thinking"
	}
	_ = ctx
	_ = deepseek.ScanSSELines(resp, func(line []byte) bool {
		chunk, done, ok := sse.ParseDeepSeekSSELine(line)
		if !ok {
			return true
		}
		if done {
			return false
		}
		if _, hasErr := chunk["error"]; hasErr {
			return false
		}
		parts, finished, newType := sse.ParseSSEChunkForContent(chunk, thinkingEnabled, currentType)
		currentType = newType
		if finished {
			return false
		}
		for _, p := range parts {
			if searchEnabled && sse.IsCitation(p.Text) {
				continue
			}
			if p.Type == "thinking" {
				thinking.WriteString(p.Text)
			} else {
				text.WriteString(p.Text)
			}
		}
		return true
	})

	finalThinking := thinking.String()
	finalText := text.String()
	detected := util.ParseToolCalls(finalText, toolNames)
	finishReason := "stop"
	messageObj := map[string]any{"role": "assistant", "content": finalText}
	if thinkingEnabled && finalThinking != "" {
		messageObj["reasoning_content"] = finalThinking
	}
	if len(detected) > 0 {
		finishReason = "tool_calls"
		messageObj["tool_calls"] = util.FormatOpenAIToolCalls(detected)
		messageObj["content"] = nil
	}
	promptTokens := util.EstimateTokens(finalPrompt)
	reasoningTokens := util.EstimateTokens(finalThinking)
	completionTokens := util.EstimateTokens(finalText)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      completionID,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{{"index": 0, "message": messageObj, "finish_reason": finishReason}},
		"usage": map[string]any{
			"prompt_tokens":     promptTokens,
			"completion_tokens": reasoningTokens + completionTokens,
			"total_tokens":      promptTokens + reasoningTokens + completionTokens,
			"completion_tokens_details": map[string]any{
				"reasoning_tokens": reasoningTokens,
			},
		},
	})
}

func (h *Handler) handleStream(w http.ResponseWriter, r *http.Request, resp *http.Response, completionID, model, finalPrompt string, thinkingEnabled, searchEnabled bool, toolNames []string) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		writeOpenAIError(w, resp.StatusCode, string(body))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	canFlush := rc.Flush() == nil
	if !canFlush {
		config.Logger.Warn("[stream] response writer does not support flush; streaming may be buffered")
	}

	lines := make(chan []byte, 128)
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 2*1024*1024)
		for scanner.Scan() {
			b := append([]byte{}, scanner.Bytes()...)
			lines <- b
		}
		close(lines)
		done <- scanner.Err()
	}()

	created := time.Now().Unix()
	firstChunkSent := false
	bufferToolContent := len(toolNames) > 0
	var toolSieve toolStreamSieveState
	toolCallsEmitted := false
	currentType := "text"
	if thinkingEnabled {
		currentType = "thinking"
	}
	thinking := strings.Builder{}
	text := strings.Builder{}
	lastContent := time.Now()
	hasContent := false
	keepaliveTicker := time.NewTicker(time.Duration(deepseek.KeepAliveTimeout) * time.Second)
	defer keepaliveTicker.Stop()
	keepaliveCountWithoutContent := 0

	sendChunk := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n\n"))
		if canFlush {
			_ = rc.Flush()
		}
	}
	sendDone := func() {
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		if canFlush {
			_ = rc.Flush()
		}
	}

	finalize := func(finishReason string) {
		finalThinking := thinking.String()
		finalText := text.String()
		detected := util.ParseToolCalls(finalText, toolNames)
		if len(detected) > 0 && !toolCallsEmitted {
			finishReason = "tool_calls"
			delta := map[string]any{
				"tool_calls": util.FormatOpenAIStreamToolCalls(detected),
			}
			if !firstChunkSent {
				delta["role"] = "assistant"
				firstChunkSent = true
			}
			sendChunk(map[string]any{
				"id":      completionID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []map[string]any{{"delta": delta, "index": 0}},
			})
		} else if bufferToolContent {
			for _, evt := range flushToolSieve(&toolSieve, toolNames) {
				if evt.Content == "" {
					continue
				}
				delta := map[string]any{
					"content": evt.Content,
				}
				if !firstChunkSent {
					delta["role"] = "assistant"
					firstChunkSent = true
				}
				sendChunk(map[string]any{
					"id":      completionID,
					"object":  "chat.completion.chunk",
					"created": created,
					"model":   model,
					"choices": []map[string]any{{"delta": delta, "index": 0}},
				})
			}
		}
		if len(detected) > 0 || toolCallsEmitted {
			finishReason = "tool_calls"
		}
		promptTokens := util.EstimateTokens(finalPrompt)
		reasoningTokens := util.EstimateTokens(finalThinking)
		completionTokens := util.EstimateTokens(finalText)
		sendChunk(map[string]any{
			"id":      completionID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{{"delta": map[string]any{}, "index": 0, "finish_reason": finishReason}},
			"usage": map[string]any{
				"prompt_tokens":     promptTokens,
				"completion_tokens": reasoningTokens + completionTokens,
				"total_tokens":      promptTokens + reasoningTokens + completionTokens,
				"completion_tokens_details": map[string]any{
					"reasoning_tokens": reasoningTokens,
				},
			},
		})
		sendDone()
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepaliveTicker.C:
			if !hasContent {
				keepaliveCountWithoutContent++
				if keepaliveCountWithoutContent >= deepseek.MaxKeepaliveCount {
					finalize("stop")
					return
				}
			}
			if hasContent && time.Since(lastContent) > time.Duration(deepseek.StreamIdleTimeout)*time.Second {
				finalize("stop")
				return
			}
			if canFlush {
				_, _ = w.Write([]byte(": keep-alive\n\n"))
				_ = rc.Flush()
			}
		case line, ok := <-lines:
			if !ok {
				// Ensure scanner completion is observed only after all queued
				// SSE lines are drained, avoiding early finalize races.
				_ = <-done
				finalize("stop")
				return
			}
			chunk, doneSignal, parsed := sse.ParseDeepSeekSSELine(line)
			if !parsed {
				continue
			}
			if doneSignal {
				finalize("stop")
				return
			}
			if _, hasErr := chunk["error"]; hasErr || chunk["code"] == "content_filter" {
				finalize("content_filter")
				return
			}
			parts, finished, newType := sse.ParseSSEChunkForContent(chunk, thinkingEnabled, currentType)
			currentType = newType
			if finished {
				finalize("stop")
				return
			}
			newChoices := make([]map[string]any, 0, len(parts))
			for _, p := range parts {
				if searchEnabled && sse.IsCitation(p.Text) {
					continue
				}
				if p.Text == "" {
					continue
				}
				hasContent = true
				lastContent = time.Now()
				keepaliveCountWithoutContent = 0
				delta := map[string]any{}
				if !firstChunkSent {
					delta["role"] = "assistant"
					firstChunkSent = true
				}
				if p.Type == "thinking" {
					if thinkingEnabled {
						thinking.WriteString(p.Text)
						delta["reasoning_content"] = p.Text
					}
				} else {
					text.WriteString(p.Text)
					if !bufferToolContent {
						delta["content"] = p.Text
					} else {
						events := processToolSieveChunk(&toolSieve, p.Text, toolNames)
						if len(events) == 0 {
							// Keep thinking delta only frame.
						}
						for _, evt := range events {
							if len(evt.ToolCalls) > 0 {
								toolCallsEmitted = true
								tcDelta := map[string]any{
									"tool_calls": util.FormatOpenAIStreamToolCalls(evt.ToolCalls),
								}
								if !firstChunkSent {
									tcDelta["role"] = "assistant"
									firstChunkSent = true
								}
								newChoices = append(newChoices, map[string]any{
									"delta": tcDelta,
									"index": 0,
								})
								continue
							}
							if evt.Content != "" {
								contentDelta := map[string]any{
									"content": evt.Content,
								}
								if !firstChunkSent {
									contentDelta["role"] = "assistant"
									firstChunkSent = true
								}
								newChoices = append(newChoices, map[string]any{
									"delta": contentDelta,
									"index": 0,
								})
							}
						}
					}
				}
				if len(delta) > 0 {
					newChoices = append(newChoices, map[string]any{"delta": delta, "index": 0})
				}
			}
			if len(newChoices) > 0 {
				sendChunk(map[string]any{
					"id":      completionID,
					"object":  "chat.completion.chunk",
					"created": created,
					"model":   model,
					"choices": newChoices,
				})
			}
		}
	}
}

func normalizeMessages(raw []any) []map[string]any {
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if ok {
			out = append(out, m)
		}
	}
	return out
}

func injectToolPrompt(messages []map[string]any, tools []any) ([]map[string]any, []string) {
	toolSchemas := make([]string, 0, len(tools))
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		tool, ok := t.(map[string]any)
		if !ok {
			continue
		}
		fn, _ := tool["function"].(map[string]any)
		if len(fn) == 0 {
			fn = tool
		}
		name, _ := fn["name"].(string)
		desc, _ := fn["description"].(string)
		schema, _ := fn["parameters"].(map[string]any)
		if name == "" {
			name = "unknown"
		}
		names = append(names, name)
		if desc == "" {
			desc = "No description available"
		}
		b, _ := json.Marshal(schema)
		toolSchemas = append(toolSchemas, fmt.Sprintf("Tool: %s\nDescription: %s\nParameters: %s", name, desc, string(b)))
	}
	if len(toolSchemas) == 0 {
		return messages, names
	}
	toolPrompt := "You have access to these tools:\n\n" + strings.Join(toolSchemas, "\n\n") + "\n\nWhen you need to use tools, output ONLY this JSON format (no other text):\n{\"tool_calls\": [{\"name\": \"tool_name\", \"input\": {\"param\": \"value\"}}]}\n\nIMPORTANT: If calling tools, output ONLY the JSON. The response must start with { and end with }"

	for i := range messages {
		if messages[i]["role"] == "system" {
			old, _ := messages[i]["content"].(string)
			messages[i]["content"] = strings.TrimSpace(old + "\n\n" + toolPrompt)
			return messages, names
		}
	}
	messages = append([]map[string]any{{"role": "system", "content": toolPrompt}}, messages...)
	return messages, names
}

func toBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeOpenAIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    openAIErrorType(status),
		},
	})
}

func openAIErrorType(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusServiceUnavailable:
		return "service_unavailable_error"
	default:
		if status >= 500 {
			return "api_error"
		}
		return "invalid_request_error"
	}
}

func isVercelStreamPrepareRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.TrimSpace(r.URL.Query().Get("__stream_prepare")) == "1"
}

func isVercelStreamReleaseRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.TrimSpace(r.URL.Query().Get("__stream_release")) == "1"
}

func vercelInternalSecret() string {
	if v := strings.TrimSpace(os.Getenv("DS2API_VERCEL_INTERNAL_SECRET")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("DS2API_ADMIN_KEY")); v != "" {
		return v
	}
	return "admin"
}

func shouldEmitBufferedToolProbeContent(buffered string) bool {
	trimmed := strings.TrimSpace(buffered)
	if trimmed == "" {
		return false
	}
	normalized := normalizeToolProbePrefix(trimmed)
	if normalized == "" {
		return false
	}
	first := normalized[0]
	switch first {
	case '{', '[', '`':
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "tool_calls") {
			return false
		}
		// Keep a short hold window for JSON-ish starts to avoid leaking tool JSON.
		if len([]rune(normalized)) < 20 {
			return false
		}
		return true
	default:
		// Natural language starts can be streamed immediately.
		return true
	}
}

func normalizeToolProbePrefix(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "```") {
		t = strings.TrimPrefix(t, "```")
		t = strings.TrimSpace(t)
		t = strings.TrimPrefix(strings.ToLower(t), "json")
		t = strings.TrimSpace(t)
	}
	return t
}

func processToolSieveChunk(state *toolStreamSieveState, chunk string, toolNames []string) []toolStreamEvent {
	if state == nil || chunk == "" {
		return nil
	}
	state.pending.WriteString(chunk)
	events := make([]toolStreamEvent, 0, 2)

	for {
		if state.capturing {
			if state.pending.Len() > 0 {
				state.capture.WriteString(state.pending.String())
				state.pending.Reset()
			}
			prefix, calls, suffix, ready := consumeToolCapture(state.capture.String(), toolNames)
			if !ready {
				break
			}
			state.capture.Reset()
			state.capturing = false
			if prefix != "" {
				events = append(events, toolStreamEvent{Content: prefix})
			}
			if len(calls) > 0 {
				events = append(events, toolStreamEvent{ToolCalls: calls})
			}
			if suffix != "" {
				state.pending.WriteString(suffix)
			}
			continue
		}

		pending := state.pending.String()
		if pending == "" {
			break
		}
		start := findToolSegmentStart(pending)
		if start >= 0 {
			prefix := pending[:start]
			if prefix != "" {
				events = append(events, toolStreamEvent{Content: prefix})
			}
			state.pending.Reset()
			state.capture.WriteString(pending[start:])
			state.capturing = true
			continue
		}

		safe, hold := splitSafeContent(pending, 64)
		if safe == "" {
			break
		}
		state.pending.Reset()
		state.pending.WriteString(hold)
		events = append(events, toolStreamEvent{Content: safe})
	}

	return events
}

func flushToolSieve(state *toolStreamSieveState, toolNames []string) []toolStreamEvent {
	if state == nil {
		return nil
	}
	events := processToolSieveChunk(state, "", toolNames)
	if state.capturing {
		raw := state.capture.String()
		state.capture.Reset()
		state.capturing = false
		if raw != "" {
			events = append(events, toolStreamEvent{Content: raw})
		}
	}
	if state.pending.Len() > 0 {
		events = append(events, toolStreamEvent{Content: state.pending.String()})
		state.pending.Reset()
	}
	return events
}

func splitSafeContent(s string, holdRunes int) (safe, hold string) {
	if s == "" || holdRunes <= 0 {
		return s, ""
	}
	runes := []rune(s)
	if len(runes) <= holdRunes {
		return "", s
	}
	return string(runes[:len(runes)-holdRunes]), string(runes[len(runes)-holdRunes:])
}

func findToolSegmentStart(s string) int {
	if s == "" {
		return -1
	}
	lower := strings.ToLower(s)
	keyIdx := strings.Index(lower, "tool_calls")
	if keyIdx < 0 {
		return -1
	}
	if start := strings.LastIndex(s[:keyIdx], "{"); start >= 0 {
		return start
	}
	return keyIdx
}

func consumeToolCapture(captured string, toolNames []string) (prefix string, calls []util.ParsedToolCall, suffix string, ready bool) {
	if captured == "" {
		return "", nil, "", false
	}
	lower := strings.ToLower(captured)
	keyIdx := strings.Index(lower, "tool_calls")
	if keyIdx < 0 {
		if len([]rune(captured)) >= 256 {
			return captured, nil, "", true
		}
		return "", nil, "", false
	}
	start := strings.LastIndex(captured[:keyIdx], "{")
	if start < 0 {
		if len([]rune(captured)) >= 512 {
			return captured, nil, "", true
		}
		return "", nil, "", false
	}
	obj, end, ok := extractJSONObjectFrom(captured, start)
	if !ok {
		if len([]rune(captured)) >= 4096 {
			return captured, nil, "", true
		}
		return "", nil, "", false
	}
	parsed := util.ParseToolCalls(obj, toolNames)
	if len(parsed) == 0 {
		return captured[:end], nil, captured[end:], true
	}
	return captured[:start], parsed, captured[end:], true
}

func extractJSONObjectFrom(text string, start int) (string, int, bool) {
	if start < 0 || start >= len(text) || text[start] != '{' {
		return "", 0, false
	}
	depth := 0
	quote := byte(0)
	escaped := false
	for i := start; i < len(text); i++ {
		ch := text[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == '{' {
			depth++
			continue
		}
		if ch == '}' {
			depth--
			if depth == 0 {
				end := i + 1
				return text[start:end], end, true
			}
		}
	}
	return "", 0, false
}

func (h *Handler) holdStreamLease(a *auth.RequestAuth) string {
	if a == nil {
		return ""
	}
	now := time.Now()
	ttl := streamLeaseTTL()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	h.leaseMu.Lock()
	expired := h.popExpiredLeasesLocked(now)
	if h.streamLeases == nil {
		h.streamLeases = make(map[string]streamLease)
	}
	leaseID := newLeaseID()
	h.streamLeases[leaseID] = streamLease{
		Auth:      a,
		ExpiresAt: now.Add(ttl),
	}
	h.leaseMu.Unlock()
	h.releaseExpiredAuths(expired)
	return leaseID
}

func (h *Handler) releaseStreamLease(leaseID string) bool {
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		return false
	}

	h.leaseMu.Lock()
	expired := h.popExpiredLeasesLocked(time.Now())
	lease, ok := h.streamLeases[leaseID]
	if ok {
		delete(h.streamLeases, leaseID)
	}
	h.leaseMu.Unlock()
	h.releaseExpiredAuths(expired)

	if !ok {
		return false
	}
	if h.Auth != nil {
		h.Auth.Release(lease.Auth)
	}
	return true
}

func (h *Handler) popExpiredLeasesLocked(now time.Time) []*auth.RequestAuth {
	if len(h.streamLeases) == 0 {
		return nil
	}
	expired := make([]*auth.RequestAuth, 0)
	for leaseID, lease := range h.streamLeases {
		if now.After(lease.ExpiresAt) {
			delete(h.streamLeases, leaseID)
			expired = append(expired, lease.Auth)
		}
	}
	return expired
}

func (h *Handler) releaseExpiredAuths(expired []*auth.RequestAuth) {
	if h.Auth == nil || len(expired) == 0 {
		return
	}
	for _, a := range expired {
		h.Auth.Release(a)
	}
}

func (h *Handler) sweepExpiredStreamLeases() {
	h.leaseMu.Lock()
	expired := h.popExpiredLeasesLocked(time.Now())
	h.leaseMu.Unlock()
	h.releaseExpiredAuths(expired)
}

func streamLeaseTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("DS2API_VERCEL_STREAM_LEASE_TTL_SECONDS"))
	if raw == "" {
		return 15 * time.Minute
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(seconds) * time.Second
}

func newLeaseID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	return fmt.Sprintf("lease-%d", time.Now().UnixNano())
}
