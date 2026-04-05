package gemini

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"ds2api/internal/deepseek"
	"ds2api/internal/sse"
	streamengine "ds2api/internal/stream"
)

func (h *Handler) handleStreamGenerateContent(w http.ResponseWriter, r *http.Request, resp *http.Response, model, finalPrompt string, thinkingEnabled, searchEnabled bool, toolNames []string) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		writeGeminiError(w, resp.StatusCode, strings.TrimSpace(string(body)))
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	rc := http.NewResponseController(w)
	_, canFlush := w.(http.Flusher)
	runtime := newGeminiStreamRuntime(w, rc, canFlush, model, finalPrompt, thinkingEnabled, searchEnabled, h.compatStripReferenceMarkers(), toolNames)

	initialType := "text"
	if thinkingEnabled {
		initialType = "thinking"
	}
	streamengine.ConsumeSSE(streamengine.ConsumeConfig{
		Context:             r.Context(),
		Body:                resp.Body,
		ThinkingEnabled:     thinkingEnabled,
		InitialType:         initialType,
		KeepAliveInterval:   time.Duration(deepseek.KeepAliveTimeout) * time.Second,
		IdleTimeout:         time.Duration(deepseek.StreamIdleTimeout) * time.Second,
		MaxKeepAliveNoInput: deepseek.MaxKeepaliveCount,
	}, streamengine.ConsumeHooks{
		OnParsed: runtime.onParsed,
		OnFinalize: func(_ streamengine.StopReason, _ error) {
			runtime.finalize()
		},
	})
}

type geminiStreamRuntime struct {
	w        http.ResponseWriter
	rc       *http.ResponseController
	canFlush bool

	model       string
	finalPrompt string

	thinkingEnabled       bool
	searchEnabled         bool
	bufferContent         bool
	stripReferenceMarkers bool
	toolNames             []string

	thinking     strings.Builder
	text         strings.Builder
	outputTokens int
}

func newGeminiStreamRuntime(
	w http.ResponseWriter,
	rc *http.ResponseController,
	canFlush bool,
	model string,
	finalPrompt string,
	thinkingEnabled bool,
	searchEnabled bool,
	stripReferenceMarkers bool,
	toolNames []string,
) *geminiStreamRuntime {
	return &geminiStreamRuntime{
		w:                     w,
		rc:                    rc,
		canFlush:              canFlush,
		model:                 model,
		finalPrompt:           finalPrompt,
		thinkingEnabled:       thinkingEnabled,
		searchEnabled:         searchEnabled,
		bufferContent:         len(toolNames) > 0,
		stripReferenceMarkers: stripReferenceMarkers,
		toolNames:             toolNames,
	}
}

func (s *geminiStreamRuntime) sendChunk(payload map[string]any) {
	b, _ := json.Marshal(payload)
	_, _ = s.w.Write([]byte("data: "))
	_, _ = s.w.Write(b)
	_, _ = s.w.Write([]byte("\n\n"))
	if s.canFlush {
		_ = s.rc.Flush()
	}
}

func (s *geminiStreamRuntime) onParsed(parsed sse.LineResult) streamengine.ParsedDecision {
	if !parsed.Parsed {
		return streamengine.ParsedDecision{}
	}
	if parsed.OutputTokens > 0 {
		s.outputTokens = parsed.OutputTokens
	}
	if parsed.ContentFilter || parsed.ErrorMessage != "" || parsed.Stop {
		return streamengine.ParsedDecision{Stop: true}
	}

	contentSeen := false
	for _, p := range parsed.Parts {
		cleanedText := cleanVisibleOutput(p.Text, s.stripReferenceMarkers)
		if cleanedText == "" {
			continue
		}
		if p.Type != "thinking" && s.searchEnabled && sse.IsCitation(cleanedText) {
			continue
		}
		contentSeen = true
		if p.Type == "thinking" {
			if s.thinkingEnabled {
				s.thinking.WriteString(cleanedText)
			}
			continue
		}
		s.text.WriteString(cleanedText)
		if s.bufferContent {
			continue
		}
		s.sendChunk(map[string]any{
			"candidates": []map[string]any{
				{
					"index": 0,
					"content": map[string]any{
						"role":  "model",
						"parts": []map[string]any{{"text": cleanedText}},
					},
				},
			},
			"modelVersion": s.model,
		})
	}
	return streamengine.ParsedDecision{ContentSeen: contentSeen}
}

func (s *geminiStreamRuntime) finalize() {
	finalThinking := s.thinking.String()
	finalText := cleanVisibleOutput(s.text.String(), s.stripReferenceMarkers)

	if s.bufferContent {
		parts := buildGeminiPartsFromFinal(finalText, finalThinking, s.toolNames)
		s.sendChunk(map[string]any{
			"candidates": []map[string]any{
				{
					"index": 0,
					"content": map[string]any{
						"role":  "model",
						"parts": parts,
					},
				},
			},
			"modelVersion": s.model,
		})
	}

	s.sendChunk(map[string]any{
		"candidates": []map[string]any{
			{
				"index": 0,
				"content": map[string]any{
					"role": "model",
					"parts": []map[string]any{
						{"text": ""},
					},
				},
				"finishReason": "STOP",
			},
		},
		"modelVersion":  s.model,
		"usageMetadata": buildGeminiUsage(s.finalPrompt, finalThinking, finalText, s.outputTokens),
	})
}
