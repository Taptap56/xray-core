package dnstt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewDialerValidation(t *testing.T) {
	if _, err := NewDialer("", "00", "1.1.1.1:53", 512); err == nil {
		t.Fatal("expected an error for empty NS, got nil")
	}
	if _, err := NewDialer("ns.example.com", "not-hex", "1.1.1.1:53", 512); err == nil {
		t.Fatal("expected an error for a non-hex pubkey, got nil")
	}
	if _, err := NewDialer("ns.example.com", "0011", "1.1.1.1:53", 512); err == nil {
		t.Fatal("expected an error for a short pubkey, got nil")
	}
	pubkey := strings.Repeat("01", 32)
	d, err := NewDialer("ns.example.com", pubkey, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if d.resolver != DefaultResolver {
		t.Fatalf("expected default resolver %s, got %s", DefaultResolver, d.resolver)
	}
	if d.kcpWindow != DefaultKCPWindow {
		t.Fatalf("expected default KCP window %d, got %d", DefaultKCPWindow, d.kcpWindow)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestDialContextRespectsContext proves a Dial to a dead server does
// not hang for the ~60 s Noise handshake timeout: it returns when
// the caller's context ends (session establishment keeps running in
// the background and a later Dial can reuse it).
func TestDialContextRespectsContext(t *testing.T) {
	pubkey := strings.Repeat("01", 32)
	d, err := NewDialer("ns.example.invalid", pubkey, "1.1.1.1:53", 512)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = d.DialContext(ctx, "tcp", "127.0.0.1:22")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error dialing a dead server, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 30*time.Second {
		t.Fatalf("DialContext took %v, expected it to return on context end", elapsed)
	}
}
