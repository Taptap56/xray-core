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

// TestParseResolver proves a user-typed resolver is normalised before
// the session is established. The standard SlowDNS forms — bare host,
// host:port and udp:// — all work; a scheme form used to reach
// establish() verbatim, where SplitHostPort/ResolveUDPAddr choke on
// the "://", so a filled resolver could never connect while an empty
// one (default 1.1.1.1:53) worked. DoH/DoT schemes (https://, tls://,
// dot://) are rejected with a clear error: the dialer is UDP-only and
// silently treating one as plain UDP would mislead the user.
func TestParseResolver(t *testing.T) {
	cases := []struct {
		in      string
		host    string
		port    string
		wantErr bool
	}{
		{"", "1.1.1.1", "53", false},
		{"1.1.1.1", "1.1.1.1", "53", false},
		{"1.1.1.1:53", "1.1.1.1", "53", false},
		{"8.8.8.8", "8.8.8.8", "53", false},
		{"8.8.8.8:53", "8.8.8.8", "53", false},
		{"8.8.8.8:5353", "8.8.8.8", "5353", false},
		{"udp://1.1.1.1:53", "1.1.1.1", "53", false},
		{"udp://1.1.1.1", "1.1.1.1", "53", false},
		{"UDP://1.1.1.1:53", "1.1.1.1", "53", false},
		{"udp://1.1.1.1:53/", "1.1.1.1", "53", false},
		{"1.1.1.1:53?x=1", "1.1.1.1", "53", false},
		{"[::1]:53", "::1", "53", false},
		{"tcp://1.1.1.1:53", "", "", true},
		{"https://1.1.1.1/dns-query", "", "", true},
		{"https://dns.google/dns-query", "", "", true},
		{"tls://1.1.1.1", "", "", true},
		{"dot://8.8.8.8:853", "", "", true},
		{"garbage:notaport", "", "", true},
		{"1.1.1.1:0", "", "", true},
		{"1.1.1.1:99999", "", "", true},
		{"://", "", "", true},
		{":53", "", "", true},
	}
	for _, c := range cases {
		host, port, err := parseResolver(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseResolver(%q): expected error, got host=%q port=%q", c.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseResolver(%q): unexpected error %v", c.in, err)
			continue
		}
		if host != c.host || port != c.port {
			t.Errorf("parseResolver(%q): got host=%q port=%q, want host=%q port=%q", c.in, host, port, c.host, c.port)
		}
	}
}

// TestNewDialerWithRecordType proves the DNS record type flows into
// the dialer: "null" selects the NULL record type (servers that only
// answer NULL, e.g. the sshvpn account proven in HTTP Custom), while
// empty defaults to TXT so existing TXT servers are unaffected.
func TestNewDialerWithRecordType(t *testing.T) {
	pubkey := strings.Repeat("01", 32)
	d, err := NewDialerWithRecordType("ns.example.com", pubkey, "1.1.1.1:53", 512, "null")
	if err != nil {
		t.Fatal(err)
	}
	if d.recordType != "null" {
		t.Fatalf("expected record type %q, got %q", "null", d.recordType)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = NewDialerWithRecordType("ns.example.com", pubkey, "1.1.1.1:53", 512, "")
	if err != nil {
		t.Fatal(err)
	}
	if d.recordType != "txt" {
		t.Fatalf("expected empty record type to default to %q, got %q", "txt", d.recordType)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	// NewDialer (no record type) keeps the old default.
	d, err = NewDialer("ns.example.com", pubkey, "1.1.1.1:53", 512)
	if err != nil {
		t.Fatal(err)
	}
	if d.recordType != "txt" {
		t.Fatalf("expected NewDialer to default to %q, got %q", "txt", d.recordType)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}
