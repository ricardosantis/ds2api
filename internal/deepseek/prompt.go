package deepseek

import "ds2api/internal/prompt"

func MessagesPrepare(messages []map[string]any) string {
	return prompt.MessagesPrepare(messages)
}

func MessagesPrepareWithThinking(messages []map[string]any, thinkingEnabled bool) string {
	return prompt.MessagesPrepareWithThinking(messages, thinkingEnabled)
}
