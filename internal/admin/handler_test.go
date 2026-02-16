package admin

import "testing"

func TestToAccountMissingFieldsRemainEmpty(t *testing.T) {
	acc := toAccount(map[string]any{
		"email":    "user@example.com",
		"password": "secret",
	})
	if acc.Email != "user@example.com" {
		t.Fatalf("unexpected email: %q", acc.Email)
	}
	if acc.Mobile != "" {
		t.Fatalf("expected empty mobile, got %q", acc.Mobile)
	}
	if acc.Token != "" {
		t.Fatalf("expected empty token, got %q", acc.Token)
	}
}

func TestFieldStringNilToEmpty(t *testing.T) {
	if got := fieldString(map[string]any{"token": nil}, "token"); got != "" {
		t.Fatalf("expected empty string for nil field, got %q", got)
	}
	if got := fieldString(map[string]any{}, "token"); got != "" {
		t.Fatalf("expected empty string for missing field, got %q", got)
	}
}
