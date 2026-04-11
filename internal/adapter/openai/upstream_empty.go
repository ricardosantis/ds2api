package openai

import "net/http"

func writeUpstreamEmptyOutputError(w http.ResponseWriter, thinking, text string, contentFilter bool) bool {
	if thinking != "" || text != "" {
		return false
	}
	if contentFilter {
		writeOpenAIErrorWithCode(w, http.StatusBadRequest, "Upstream content filtered the response and returned no output.", "content_filter")
		return true
	}
	writeOpenAIErrorWithCode(w, http.StatusTooManyRequests, "Upstream model returned empty output.", "upstream_empty_output")
	return true
}
