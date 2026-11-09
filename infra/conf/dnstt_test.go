package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/dnstt"
)

func TestDNSTTConfig(t *testing.T) {
	creator := func() Buildable {
		return new(DNSTTClientConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"dnsttNs": "ns.example.com",
				"dnsttPubkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				"dnsttResolver": "1.1.1.1:53",
				"dnsttKcpWindow": 512,
				"dnsttRecordType": "null"
			}`,
			Parser: loadJSON(creator),
			Output: &dnstt.Config{
				Ns:         "ns.example.com",
				Pubkey:     "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				Resolver:   "1.1.1.1:53",
				KcpWindow:  512,
				RecordType: "null",
			},
		},
		{
			// Empty record type and resolver mean the core defaults
			// (TXT, 1.1.1.1:53): existing TXT servers are unaffected.
			Input: `{
				"dnsttNs": "ns.example.com",
				"dnsttPubkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
			}`,
			Parser: loadJSON(creator),
			Output: &dnstt.Config{
				Ns:     "ns.example.com",
				Pubkey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			},
		},
	})
}

func TestDNSTTConfigMissingNS(t *testing.T) {
	config := new(DNSTTClientConfig)
	if err := json.Unmarshal([]byte(`{"dnsttPubkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}`), config); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(); err == nil {
		t.Fatal("expected an error for missing dnsttNs, got nil")
	}
}

// TestDNSTTOutboundDetour proves the "dnstt" protocol id is registered
// in the outbound JSON config loader: a full outbound detour builds
// into an OutboundHandlerConfig whose proxy settings are the dnstt
// config.
func TestDNSTTOutboundDetour(t *testing.T) {
	raw := `{
		"protocol": "dnstt",
		"tag": "dnstt",
		"settings": {
			"dnsttNs": "ns.example.com",
			"dnsttPubkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			"dnsttResolver": "1.1.1.1:53",
			"dnsttKcpWindow": 512,
			"dnsttRecordType": "txt"
		}
	}`
	config := new(OutboundDetourConfig)
	if err := json.Unmarshal([]byte(raw), config); err != nil {
		t.Fatal(err)
	}
	handler, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	if handler.Tag != "dnstt" {
		t.Fatalf("unexpected tag: %s", handler.Tag)
	}
	if handler.ProxySettings == nil || !strings.Contains(handler.ProxySettings.Type, "xray.proxy.dnstt.Config") {
		t.Fatalf("proxy settings are not the dnstt config: %+v", handler.ProxySettings)
	}
}
