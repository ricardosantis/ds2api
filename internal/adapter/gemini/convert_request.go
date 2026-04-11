package gemini

import (
	"fmt"
	"strings"

	"ds2api/internal/adapter/openai"
	"ds2api/internal/config"
	"ds2api/internal/util"
)

//nolint:unused // kept for native Gemini adapter route compatibility.
func normalizeGeminiRequest(store ConfigReader, routeModel string, req map[string]any, stream bool) (util.StandardRequest, error) {
	requestedModel := strings.TrimSpace(routeModel)
	if requestedModel == "" {
		return util.StandardRequest{}, fmt.Errorf("model is required in request path")
	}

	resolvedModel, ok := config.ResolveModel(store, requestedModel)
	if !ok {
		return util.StandardRequest{}, fmt.Errorf("model %q is not available", requestedModel)
	}
	thinkingEnabled, searchEnabled, _ := config.GetModelConfig(resolvedModel)

	messagesRaw := geminiMessagesFromRequest(req)
	if len(messagesRaw) == 0 {
		return util.StandardRequest{}, fmt.Errorf("request must include non-empty contents")
	}

	toolsRaw := convertGeminiTools(req["tools"])
	finalPrompt, toolNames := openai.BuildPromptForAdapter(messagesRaw, toolsRaw, "")
	passThrough := collectGeminiPassThrough(req)

	return util.StandardRequest{
		Surface:        "google_gemini",
		RequestedModel: requestedModel,
		ResolvedModel:  resolvedModel,
		ResponseModel:  requestedModel,
		Messages:       messagesRaw,
		FinalPrompt:    finalPrompt,
		ToolNames:      toolNames,
		Stream:         stream,
		Thinking:       thinkingEnabled,
		Search:         searchEnabled,
		PassThrough:    passThrough,
	}, nil
}
