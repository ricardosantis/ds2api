package config

import (
	"strings"
	"testing"
)

func TestAccountIdentifierFallsBackToTokenHash(t *testing.T) {
	acc := Account{Token: "example-token-value"}
	id := acc.Identifier()
	if !strings.HasPrefix(id, "token:") {
		t.Fatalf("expected token-prefixed identifier, got %q", id)
	}
	if len(id) != len("token:")+16 {
		t.Fatalf("unexpected identifier length: %d (%q)", len(id), id)
	}
}

func TestStoreFindAccountWithTokenOnlyIdentifier(t *testing.T) {
	t.Setenv("DS2API_CONFIG_JSON", `{
		"keys":["k1"],
		"accounts":[{"token":"token-only-account"}]
	}`)

	store := LoadStore()
	accounts := store.Accounts()
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accounts))
	}
	id := accounts[0].Identifier()
	if id == "" {
		t.Fatalf("expected synthetic identifier for token-only account")
	}
	found, ok := store.FindAccount(id)
	if !ok {
		t.Fatalf("expected FindAccount to locate token-only account by synthetic id")
	}
	if found.Token != "token-only-account" {
		t.Fatalf("unexpected token value: %q", found.Token)
	}
}
