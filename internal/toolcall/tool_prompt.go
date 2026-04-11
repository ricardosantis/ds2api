package toolcall

import "strings"

// BuildToolCallInstructions generates the unified tool-calling instruction block
// used by all adapters (OpenAI, Claude, Gemini). It uses attention-optimized
// structure: rules → negative examples → positive examples → anchor.
//
// The toolNames slice should contain the actual tool names available in the
// current request; the function picks real names for examples.
func BuildToolCallInstructions(toolNames []string) string {
	// Pick real tool names for examples; fall back to generic names.
	ex1 := "read_file"
	ex2 := "write_to_file"
	ex3 := "ask_followup_question"
	used := map[string]bool{}
	for _, n := range toolNames {
		switch {
		// Read/query-type tools
		case !used["ex1"] && matchAny(n, "read_file", "list_files", "search_files", "Read", "Glob"):
			ex1 = n
			used["ex1"] = true
		// Write/execute-type tools
		case !used["ex2"] && matchAny(n, "write_to_file", "apply_diff", "execute_command", "exec_command", "Write", "Edit", "MultiEdit", "Bash"):
			ex2 = n
			used["ex2"] = true
		// Interactive/meta tools
		case !used["ex3"] && matchAny(n, "ask_followup_question", "attempt_completion", "update_todo_list", "Task"):
			ex3 = n
			used["ex3"] = true
		}
	}
	ex1Params := exampleReadParams(ex1)
	ex2Params := exampleWriteOrExecParams(ex2)
	ex3Params := exampleInteractiveParams(ex3)

	return `TOOL CALL FORMAT — FOLLOW EXACTLY:

When calling tools, emit ONLY raw XML at the very end of your response. No text before, no text after, no markdown fences.

<tool_calls>
  <tool_call>
    <tool_name>TOOL_NAME_HERE</tool_name>
    <parameters>{"key":"value"}</parameters>
  </tool_call>
</tool_calls>

RULES:
1) When calling tools, you MUST use the <tool_calls> XML format.
2) No text is allowed AFTER the XML block.
3) <parameters> MUST be a single-line strict JSON object. Use double quotes.
4) Multiple tools must be inside the same <tool_calls> root.
5) Do NOT wrap XML in markdown fences (` + "```" + `).
6) Do NOT invent parameters. Use only the provided schema.
7) CRITICAL: Do NOT use native tool markers like "<｜Tool｜>" or "<｜tool｜>".
8) CRITICAL: Do NOT output role markers like "<｜System｜>", "<｜User｜>", or "<｜Assistant｜>".
9) CRITICAL: Do NOT output internal monologues (e.g. "I will list files now..."). Just output your answer or the XML.

❌ WRONG — Do NOT do these:
Wrong 1 — mixed text after XML:
  <tool_calls>...</tool_calls> I hope this helps.
Wrong 2 — function-call syntax:
  Grep({"pattern": "token"})
Wrong 3 — missing <tool_calls> wrapper:
  <tool_call><tool_name>` + ex1 + `</tool_name><parameters>{}</parameters></tool_call>
Wrong 4 — Markdown code fences:
  ` + "```xml" + `
  <tool_calls>...</tool_calls>
  ` + "```" + `
Wrong 5 — native tool tokens:
  <｜Tool｜>call_some_tool{"param":1}<｜Tool｜>
Wrong 6 — role markers in response:
  <｜Assistant｜> Here is the result...

Remember: The ONLY valid way to use tools is the <tool_calls> XML block at the end of your response.

✅ CORRECT EXAMPLES:

Example A — Single tool:
<tool_calls>
  <tool_call>
    <tool_name>` + ex1 + `</tool_name>
    <parameters>` + ex1Params + `</parameters>
  </tool_call>
</tool_calls>

Example B — Two tools in parallel:
<tool_calls>
  <tool_call>
    <tool_name>` + ex1 + `</tool_name>
    <parameters>` + ex1Params + `</parameters>
  </tool_call>
  <tool_call>
    <tool_name>` + ex2 + `</tool_name>
    <parameters>` + ex2Params + `</parameters>
  </tool_call>
</tool_calls>

Example C — Tool with complex nested JSON parameters:
<tool_calls>
  <tool_call>
    <tool_name>` + ex3 + `</tool_name>
    <parameters>` + ex3Params + `</parameters>
  </tool_call>
</tool_calls>

Remember: Output ONLY the <tool_calls>...</tool_calls> XML block when calling tools.`
}

func matchAny(name string, candidates ...string) bool {
	for _, c := range candidates {
		if name == c {
			return true
		}
	}
	return false
}

func exampleReadParams(name string) string {
	switch strings.TrimSpace(name) {
	case "Read":
		return `{"file_path":"README.md"}`
	case "Glob":
		return `{"pattern":"**/*.go","path":"."}`
	default:
		return `{"path":"src/main.go"}`
	}
}

func exampleWriteOrExecParams(name string) string {
	switch strings.TrimSpace(name) {
	case "Bash", "execute_command":
		return `{"command":"pwd"}`
	case "exec_command":
		return `{"cmd":"pwd"}`
	case "Edit":
		return `{"file_path":"README.md","old_string":"foo","new_string":"bar"}`
	case "MultiEdit":
		return `{"file_path":"README.md","edits":[{"old_string":"foo","new_string":"bar"}]}`
	default:
		return `{"path":"output.txt","content":"Hello world"}`
	}
}

func exampleInteractiveParams(name string) string {
	switch strings.TrimSpace(name) {
	case "Task":
		return `{"description":"Investigate flaky tests","prompt":"Run targeted tests and summarize failures"}`
	default:
		return `{"question":"Which approach do you prefer?","follow_up":[{"text":"Option A"},{"text":"Option B"}]}`
	}
}
