package openai

import (
	"strings"

	"ds2api/internal/util"
)

func processToolSieveChunk(state *toolStreamSieveState, chunk string, toolNames []string) []toolStreamEvent {
	if state == nil {
		return nil
	}
	if chunk != "" {
		state.pending.WriteString(chunk)
	}
	events := make([]toolStreamEvent, 0, 2)
	if len(state.pendingToolCalls) > 0 {
		events = append(events, toolStreamEvent{ToolCalls: state.pendingToolCalls})
		state.pendingToolRaw = ""
		state.pendingToolCalls = nil
	}

	for {
		if state.capturing {
			if state.pending.Len() > 0 {
				state.capture.WriteString(state.pending.String())
				state.pending.Reset()
			}
			prefix, calls, suffix, ready := consumeToolCapture(state, toolNames)
			if !ready {
				break
			}
			captured := state.capture.String()
			state.capture.Reset()
			state.capturing = false
			state.resetIncrementalToolState()
			if len(calls) > 0 {
				if prefix != "" {
					state.noteText(prefix)
					events = append(events, toolStreamEvent{Content: prefix})
				}
				if suffix != "" {
					state.pending.WriteString(suffix)
				}
				_ = captured
				state.pendingToolCalls = calls
				continue
			}
			if prefix != "" {
				state.noteText(prefix)
				events = append(events, toolStreamEvent{Content: prefix})
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
				state.noteText(prefix)
				events = append(events, toolStreamEvent{Content: prefix})
			}
			state.pending.Reset()
			state.capture.WriteString(pending[start:])
			state.capturing = true
			state.resetIncrementalToolState()
			continue
		}

		safe, hold := splitSafeContentForToolDetection(pending)
		if safe == "" {
			break
		}
		state.pending.Reset()
		state.pending.WriteString(hold)
		state.noteText(safe)
		events = append(events, toolStreamEvent{Content: safe})
	}

	return events
}

func flushToolSieve(state *toolStreamSieveState, toolNames []string) []toolStreamEvent {
	if state == nil {
		return nil
	}
	events := processToolSieveChunk(state, "", toolNames)
	if len(state.pendingToolCalls) > 0 {
		events = append(events, toolStreamEvent{ToolCalls: state.pendingToolCalls})
		state.pendingToolRaw = ""
		state.pendingToolCalls = nil
	}
	if state.capturing {
		consumedPrefix, consumedCalls, consumedSuffix, ready := consumeToolCapture(state, toolNames)
		if ready {
			if consumedPrefix != "" {
				state.noteText(consumedPrefix)
				events = append(events, toolStreamEvent{Content: consumedPrefix})
			}
			if len(consumedCalls) > 0 {
				events = append(events, toolStreamEvent{ToolCalls: consumedCalls})
			}
			if consumedSuffix != "" {
				state.noteText(consumedSuffix)
				events = append(events, toolStreamEvent{Content: consumedSuffix})
			}
		} else {
			content := state.capture.String()
			if content != "" {
				state.noteText(content)
				events = append(events, toolStreamEvent{Content: content})
			}
		}
		state.capture.Reset()
		state.capturing = false
		state.resetIncrementalToolState()
	}
	if state.pending.Len() > 0 {
		content := state.pending.String()
		state.noteText(content)
		events = append(events, toolStreamEvent{Content: content})
		state.pending.Reset()
	}
	return events
}

func splitSafeContentForToolDetection(s string) (safe, hold string) {
	if s == "" {
		return "", ""
	}
	suspiciousStart := findSuspiciousPrefixStart(s)
	if suspiciousStart < 0 {
		return s, ""
	}
	if suspiciousStart > 0 {
		return s[:suspiciousStart], s[suspiciousStart:]
	}
	// If suspicious content starts at position 0, keep holding until we can
	// parse a complete tool JSON block or reach stream flush.
	return "", s
}

func findSuspiciousPrefixStart(s string) int {
	start := -1
	indices := []int{
		strings.LastIndex(s, "{"),
		strings.LastIndex(s, "["),
		strings.LastIndex(s, "```"),
	}
	for _, idx := range indices {
		if idx > start {
			start = idx
		}
	}
	return start
}

func findToolSegmentStart(s string) int {
	if s == "" {
		return -1
	}
	lower := strings.ToLower(s)
	keywords := []string{"tool_calls", "function.name:", "[tool_call_history]", "[tool_result_history]"}
	bestKeyIdx := -1
	for _, kw := range keywords {
		idx := strings.Index(lower, kw)
		if idx >= 0 && (bestKeyIdx < 0 || idx < bestKeyIdx) {
			bestKeyIdx = idx
		}
	}
	if bestKeyIdx < 0 {
		return -1
	}
	start := strings.LastIndex(s[:bestKeyIdx], "{")
	if start < 0 {
		start = bestKeyIdx
	}
	if fenceStart, ok := openFenceStartBefore(s, start); ok {
		return fenceStart
	}
	return start
}

func consumeToolCapture(state *toolStreamSieveState, toolNames []string) (prefix string, calls []util.ParsedToolCall, suffix string, ready bool) {
	captured := state.capture.String()
	if captured == "" {
		return "", nil, "", false
	}
	lower := strings.ToLower(captured)
	keyIdx := -1
	keywords := []string{"tool_calls", "function.name:", "[tool_call_history]", "[tool_result_history]"}
	for _, kw := range keywords {
		idx := strings.Index(lower, kw)
		if idx >= 0 && (keyIdx < 0 || idx < keyIdx) {
			keyIdx = idx
		}
	}

	if keyIdx < 0 {
		return "", nil, "", false
	}
	start := strings.LastIndex(captured[:keyIdx], "{")
	if start < 0 {
		if blockStart, blockEnd, ok := extractToolHistoryBlock(captured, keyIdx); ok {
			return captured[:blockStart], nil, captured[blockEnd:], true
		}
		start = keyIdx
	}
	obj, end, ok := extractJSONObjectFrom(captured, start)
	if !ok {
		return "", nil, "", false
	}
	prefixPart := captured[:start]
	suffixPart := captured[end:]
	parsed := util.ParseStandaloneToolCallsDetailed(obj, toolNames)
	if len(parsed.Calls) == 0 {
		if parsed.SawToolCallSyntax && parsed.RejectedByPolicy {
			// Parsed as tool-call payload but rejected by schema/policy:
			// consume it to avoid leaking raw tool_calls JSON to user content.
			return prefixPart, nil, suffixPart, true
		}
		// If it has obvious keywords but failed to parse even after loose repair,
		// we still might want to intercept it if it looks like an attempt at tool call.
		// For now, keep the original logic but rely on loose JSON repair.
		return captured, nil, "", true
	}
	prefixPart, suffixPart = trimWrappingJSONFence(prefixPart, suffixPart)
	return prefixPart, parsed.Calls, suffixPart, true
}

func extractToolHistoryBlock(captured string, keyIdx int) (start int, end int, ok bool) {
	if keyIdx < 0 || keyIdx >= len(captured) {
		return 0, 0, false
	}
	rest := strings.ToLower(captured[keyIdx:])
	switch {
	case strings.HasPrefix(rest, "[tool_call_history]"):
		closeTag := "[/tool_call_history]"
		closeIdx := strings.Index(rest, closeTag)
		if closeIdx < 0 {
			return 0, 0, false
		}
		return keyIdx, keyIdx + closeIdx + len(closeTag), true
	case strings.HasPrefix(rest, "[tool_result_history]"):
		closeTag := "[/tool_result_history]"
		closeIdx := strings.Index(rest, closeTag)
		if closeIdx < 0 {
			return 0, 0, false
		}
		return keyIdx, keyIdx + closeIdx + len(closeTag), true
	default:
		return 0, 0, false
	}
}

func trimWrappingJSONFence(prefix, suffix string) (string, string) {
	trimmedPrefix := strings.TrimRight(prefix, " \t\r\n")
	fenceIdx := strings.LastIndex(trimmedPrefix, "```")
	if fenceIdx < 0 {
		return prefix, suffix
	}
	// Only strip when the trailing fence in prefix behaves like an opening fence.
	// A legitimate closing fence before a standalone tool JSON must be preserved.
	if strings.Count(trimmedPrefix[:fenceIdx+3], "```")%2 == 0 {
		return prefix, suffix
	}
	fenceHeader := strings.TrimSpace(trimmedPrefix[fenceIdx+3:])
	if fenceHeader != "" && !strings.EqualFold(fenceHeader, "json") {
		return prefix, suffix
	}

	trimmedSuffix := strings.TrimLeft(suffix, " \t\r\n")
	if !strings.HasPrefix(trimmedSuffix, "```") {
		return prefix, suffix
	}
	consumedLeading := len(suffix) - len(trimmedSuffix)
	return trimmedPrefix[:fenceIdx], suffix[consumedLeading+3:]
}

func openFenceStartBefore(s string, pos int) (int, bool) {
	if pos <= 0 || pos > len(s) {
		return -1, false
	}
	segment := s[:pos]
	lastFence := strings.LastIndex(segment, "```")
	if lastFence < 0 {
		return -1, false
	}
	if strings.Count(segment, "```")%2 == 1 {
		return lastFence, true
	}
	return -1, false
}
