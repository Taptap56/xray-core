package dnstt

import (
	"context"
	"strings"
	"testing"
)

// TestNewClientRejectsBadSettings proves the handler validates its
// DNSTT settings before any network I/O or feature lookup: a nil
// config, an empty NS, and a bad public key are all rejected.
// (A valid config still needs a policy.Manager feature to construct,
// which only a full core provides — that path is covered by the
// scenario and conf tests.)
func TestNewClientRejectsBadSettings(t *testing.T) {
	if _, err := NewClient(context.Background(), nil); err == nil {
		t.Fatal("expected an error for nil config, got nil")
	}
	pubkey := strings.Repeat("01", 32)
	if _, err := NewClient(context.Background(), &Config{Pubkey: pubkey}); err == nil {
		t.Fatal("expected an error for empty NS, got nil")
	}
	if _, err := NewClient(context.Background(), &Config{Ns: "ns.example.com", Pubkey: "not-hex"}); err == nil {
		t.Fatal("expected an error for a non-hex pubkey, got nil")
	}
	if _, err := NewClient(context.Background(), &Config{Ns: "ns.example.com", Pubkey: "0011"}); err == nil {
		t.Fatal("expected an error for a short pubkey, got nil")
	}
}
