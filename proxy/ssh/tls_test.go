package ssh

import (
	"crypto/tls"
	"testing"
)

func TestTLSVersionRange(t *testing.T) {
	cases := []struct {
		version   string
		wantMin   uint16
		wantMax   uint16
		expectErr bool
	}{
		{"", 0, 0, false},        // empty = default (auto)
		{"default", 0, 0, false}, // explicit default = auto
		{"Default", 0, 0, false}, // case-insensitive
		{"tls1", tls.VersionTLS10, tls.VersionTLS10, false},
		{"tls1.1", tls.VersionTLS11, tls.VersionTLS11, false},
		{"tls1.2", tls.VersionTLS12, tls.VersionTLS12, false},
		{"tls1.3", tls.VersionTLS13, tls.VersionTLS13, false},
		{"TLS1.2", tls.VersionTLS12, tls.VersionTLS12, false},
		{"tls1.0", 0, 0, true}, // not a valid name
		{"ssl3", 0, 0, true},   // not a valid name
		{"bogus", 0, 0, true},
	}
	for _, tc := range cases {
		min, max, err := tlsVersionRange(tc.version)
		if tc.expectErr {
			if err == nil {
				t.Errorf("tlsVersionRange(%q): expected error, got nil", tc.version)
			}
			continue
		}
		if err != nil {
			t.Errorf("tlsVersionRange(%q): unexpected error: %v", tc.version, err)
			continue
		}
		if min != tc.wantMin || max != tc.wantMax {
			t.Errorf("tlsVersionRange(%q) = (%v, %v), want (%v, %v)",
				tc.version, min, max, tc.wantMin, tc.wantMax)
		}
	}
}

func TestBuildTLSConfig(t *testing.T) {
	// Default: no forced version, ServerName set, verify on.
	cfg, err := buildTLSConfig("example.com", "default", false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "example.com")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false")
	}
	if cfg.MinVersion != 0 || cfg.MaxVersion != 0 {
		t.Errorf("default version = (%v, %v), want (0, 0)", cfg.MinVersion, cfg.MaxVersion)
	}

	// Explicit version pins min and max; insecure skips verification.
	cfg, err = buildTLSConfig("example.com", "tls1.2", true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tls.VersionTLS12 {
		t.Errorf("tls1.2 = (%v, %v), want (%v, %v)",
			cfg.MinVersion, cfg.MaxVersion, tls.VersionTLS12, tls.VersionTLS12)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}

	// Unknown version is an error.
	if _, err := buildTLSConfig("example.com", "tls9", false); err == nil {
		t.Error("expected an error for unknown version, got nil")
	}
}

func TestEffectiveMethod(t *testing.T) {
	// Empty method, no DNSTT: direct.
	c := &Client{config: &Config{Address: "example.com"}}
	if got := c.effectiveMethod(); got != methodDirect {
		t.Errorf("empty method = %q, want %q", got, methodDirect)
	}
	// Explicit methods pass through (case-insensitive, trimmed).
	for _, m := range []string{"payload", "ws", "ws-tls", "tls", "slowdns", "direct"} {
		c.config.Method = m
		if got := c.effectiveMethod(); got != m {
			t.Errorf("method %q = %q, want %q", m, got, m)
		}
	}
	c.config.Method = " WS-TLS "
	if got := c.effectiveMethod(); got != methodWSTLS {
		t.Errorf("method with spaces/case = %q, want %q", got, methodWSTLS)
	}
}
