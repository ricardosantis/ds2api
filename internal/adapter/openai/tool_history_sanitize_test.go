package openai

import "testing"

func TestSanitizeLeakedToolHistoryRemovesMarkerBlocks(t *testing.T) {
	raw := "前缀\n[TOOL_CALL_HISTORY]\nfunction.name: exec\nfunction.arguments: {}\n[/TOOL_CALL_HISTORY]\n后缀"
	got := sanitizeLeakedToolHistory(raw)
	if got != "前缀\n\n后缀" {
		t.Fatalf("unexpected sanitized content: %q", got)
	}
}

func TestSanitizeLeakedToolHistoryPreservesChunkWhitespace(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "trailing space kept",
			raw:  "Hello ",
			want: "Hello ",
		},
		{
			name: "leading newline kept",
			raw:  "\nworld",
			want: "\nworld",
		},
		{
			name: "surrounding whitespace around marker is preserved",
			raw:  "A \n[TOOL_RESULT_HISTORY]\nfunction.name: exec\nfunction.arguments: {}\n[/TOOL_RESULT_HISTORY]\n B",
			want: "A \n\n B",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeLeakedToolHistory(tc.raw)
			if got != tc.want {
				t.Fatalf("unexpected sanitize result, want %q got %q", tc.want, got)
			}
		})
	}
}

func TestFlushToolSieveDropsToolHistoryLeak(t *testing.T) {
	var state toolStreamSieveState
	chunk := "[TOOL_CALL_HISTORY]\nstatus: already_called\nfunction.name: exec\nfunction.arguments: {}\n[/TOOL_CALL_HISTORY]"
	evts := processToolSieveChunk(&state, chunk, []string{"exec"})
	if len(evts) != 0 {
		t.Fatalf("expected no immediate output before history block is complete, got %+v", evts)
	}
	flushed := flushToolSieve(&state, []string{"exec"})
	if len(flushed) != 0 {
		t.Fatalf("expected history block to be swallowed, got %+v", flushed)
	}
}

func TestFlushToolSieveDropsToolResultHistoryLeak(t *testing.T) {
	var state toolStreamSieveState
	chunk := "[TOOL_RESULT_HISTORY]\nstatus: already_called\nfunction.name: exec\nfunction.arguments: {}\n[/TOOL_RESULT_HISTORY]"
	evts := processToolSieveChunk(&state, chunk, []string{"exec"})
	if len(evts) != 0 {
		t.Fatalf("expected no immediate output before result history block is complete, got %+v", evts)
	}
	flushed := flushToolSieve(&state, []string{"exec"})
	if len(flushed) != 0 {
		t.Fatalf("expected result history block to be swallowed, got %+v", flushed)
	}
}

func TestProcessToolSieveChunkSplitsResultHistoryBoundary(t *testing.T) {
	var state toolStreamSieveState
	parts := []string{
		"Hello ",
		"[TOOL_RESULT_HISTORY]\nstatus: already_called\n",
		"function.name: exec\nfunction.arguments: {}\n[/TOOL_RESULT_HISTORY]",
		"world",
	}
	var events []toolStreamEvent
	for _, p := range parts {
		events = append(events, processToolSieveChunk(&state, p, []string{"exec"})...)
	}
	events = append(events, flushToolSieve(&state, []string{"exec"})...)

	var text string
	for _, evt := range events {
		if evt.Content != "" {
			text += evt.Content
		}
		if len(evt.ToolCalls) > 0 {
			t.Fatalf("did not expect parsed tool calls from history leak: %+v", evt.ToolCalls)
		}
	}
	if text != "Hello world" {
		t.Fatalf("expected clean text output preserving boundary spaces, got %q", text)
	}
}
