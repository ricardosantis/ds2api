package config

import "testing"

func TestStoreHistorySplitAccessors(t *testing.T) {
	store := &Store{cfg: Config{}}
	if !store.HistorySplitEnabled() {
		t.Fatal("expected history split enabled by default")
	}
	if got := store.HistorySplitTriggerAfterTurns(); got != 1 {
		t.Fatalf("default history split trigger_after_turns=%d want=1", got)
	}

	enabled := false
	turns := 3
	store.cfg.HistorySplit = HistorySplitConfig{
		Enabled:           &enabled,
		TriggerAfterTurns: &turns,
	}

	if store.HistorySplitEnabled() {
		t.Fatal("expected history split disabled after override")
	}
	if got := store.HistorySplitTriggerAfterTurns(); got != 3 {
		t.Fatalf("history split trigger_after_turns=%d want=3", got)
	}
}
