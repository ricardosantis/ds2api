package openai

import (
	"regexp"
)

var leakedToolHistoryPattern = regexp.MustCompile(`(?is)\[TOOL_CALL_HISTORY\][\s\S]*?\[/TOOL_CALL_HISTORY\]|\[TOOL_RESULT_HISTORY\][\s\S]*?\[/TOOL_RESULT_HISTORY\]`)

func sanitizeLeakedToolHistory(text string) string {
	if text == "" {
		return text
	}
	return leakedToolHistoryPattern.ReplaceAllString(text, "")
}
