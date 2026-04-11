package claude

import "testing"

type mockClaudeConfig struct {
	m map[string]string
}

func (m mockClaudeConfig) ClaudeMapping() map[string]string { return m.m }
func (mockClaudeConfig) CompatStripReferenceMarkers() bool  { return true }

func TestNormalizeClaudeRequestUsesConfigInterfaceMapping(t *testing.T) {
	req := map[string]any{
		"model": "claude-opus-4-6",
		"messages": []any{
			map[string]any{"role": "user", "content": "hello"},
		},
	}
	out, err := normalizeClaudeRequest(mockClaudeConfig{
		m: map[string]string{
			"fast": "deepseek-chat",
			"slow": "deepseek-reasoner-search",
		},
	}, req)
	if err != nil {
		t.Fatalf("normalizeClaudeRequest error: %v", err)
	}
	if out.Standard.ResolvedModel != "deepseek-reasoner-search" {
		t.Fatalf("resolved model mismatch: got=%q", out.Standard.ResolvedModel)
	}
	if !out.Standard.Thinking || !out.Standard.Search {
		t.Fatalf("unexpected flags: thinking=%v search=%v", out.Standard.Thinking, out.Standard.Search)
	}
}
