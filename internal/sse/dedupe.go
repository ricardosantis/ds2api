package sse

import "strings"

const minContinuationSnapshotLen = 32

// TrimContinuationOverlap removes the already-seen prefix when DeepSeek
// continue rounds resend the full fragment snapshot instead of only the new
// suffix. Non-overlapping chunks are returned unchanged.
func TrimContinuationOverlap(existing, incoming string) string {
	if incoming == "" {
		return ""
	}
	if existing == "" {
		return incoming
	}
	if len(incoming) >= minContinuationSnapshotLen && strings.HasPrefix(incoming, existing) {
		return incoming[len(existing):]
	}
	if len(incoming) >= minContinuationSnapshotLen && strings.HasPrefix(existing, incoming) {
		return ""
	}
	return incoming
}
