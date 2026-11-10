package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/ssh"
)

func TestSSHConfig(t *testing.T) {
	creator := func() Buildable {
		return new(SSHClientConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"address": "ssh.example.com",
				"port": 2222,
				"username": "alice",
				"password": "secret",
				"dnsttNs": "ns.example.com",
				"dnsttPubkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				"dnsttResolver": "1.1.1.1:53",
				"dnsttKcpWindow": 512
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:        "ssh.example.com",
				Port:           2222,
				Username:       "alice",
				Password:       "secret",
				DnsttNs:        "ns.example.com",
				DnsttPubkey:    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				DnsttResolver:  "1.1.1.1:53",
				DnsttKcpWindow: 512,
			},
		},
		{
			// Record type "null" round-trips: servers that only answer
			// NULL (proven by HTTP Custom for one account) need it.
			Input: `{
				"address": "ssh.example.com",
				"port": 22,
				"username": "alice",
				"password": "secret",
				"dnsttNs": "ns.example.com",
				"dnsttPubkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				"dnsttResolver": "1.1.1.1:53",
				"dnsttKcpWindow": 512,
				"dnsttRecordType": "null"
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:         "ssh.example.com",
				Port:            22,
				Username:        "alice",
				Password:        "secret",
				DnsttNs:         "ns.example.com",
				DnsttPubkey:     "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				DnsttResolver:   "1.1.1.1:53",
				DnsttKcpWindow:  512,
				DnsttRecordType: "null",
			},
		},
		{
			// Port 0 defaults to 22; no DNSTT fields means direct dial.
			Input: `{
				"address": "10.0.0.1",
				"username": "bob",
				"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:    "10.0.0.1",
				Port:       22,
				Username:   "bob",
				PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
			},
		},
		{
			// HTTP Custom style layers round-trip: payload + TLS
			// together, with a remote proxy, SNI, pinned TLS
			// version and insecure.
			Input: `{
				"address": "ssh.example.com",
				"port": 443,
				"username": "alice",
				"password": "secret",
				"usePayload": true,
				"useTls": true,
				"remoteProxy": "user:pass@proxy.example.com:8080",
				"payload": "GET / HTTP/1.1\nHost: [host]\n\n",
				"sni": "sni.example.com",
				"sniVersion": "tls1.2",
				"insecure": true
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:     "ssh.example.com",
				Port:        443,
				Username:    "alice",
				Password:    "secret",
				UsePayload:  true,
				UseTls:      true,
				RemoteProxy: "user:pass@proxy.example.com:8080",
				Payload:     "GET / HTTP/1.1\nHost: [host]\n\n",
				Sni:         "sni.example.com",
				SniVersion:  "tls1.2",
				Insecure:    true,
			},
		},
		{
			// Payload layer round-trips the template verbatim
			// (substitution happens at dial time, not in Build).
			Input: `{
				"address": "ssh.example.com",
				"port": 3128,
				"username": "alice",
				"password": "secret",
				"usePayload": true,
				"payload": "GET / HTTP/1.1\nHost: [host]\n\n"
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:    "ssh.example.com",
				Port:       3128,
				Username:   "alice",
				Password:   "secret",
				UsePayload: true,
				Payload:    "GET / HTTP/1.1\nHost: [host]\n\n",
			},
		},
		{
			// Legacy "method" migrates to the layer flags when no
			// layer flag is set: "payload" -> usePayload.
			Input: `{
				"address": "ssh.example.com",
				"port": 3128,
				"username": "alice",
				"password": "secret",
				"method": "payload",
				"payload": "GET / HTTP/1.1\nHost: [host]\n\n"
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:    "ssh.example.com",
				Port:       3128,
				Username:   "alice",
				Password:   "secret",
				UsePayload: true,
				Payload:    "GET / HTTP/1.1\nHost: [host]\n\n",
			},
		},
		{
			// Legacy "ws-tls" migrates to direct: the WS dial was
			// removed (HTTP Custom has no WS transport for SSH).
			Input: `{
				"address": "ssh.example.com",
				"port": 443,
				"username": "alice",
				"password": "secret",
				"method": "ws-tls",
				"sni": "sni.example.com",
				"sniVersion": "tls1.2",
				"insecure": true
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:    "ssh.example.com",
				Port:       443,
				Username:   "alice",
				Password:   "secret",
				Sni:        "sni.example.com",
				SniVersion: "tls1.2",
				Insecure:   true,
			},
		},
		{
			// Legacy "slowdns" migrates to the slowdns layer.
			Input: `{
				"address": "ssh.example.com",
				"port": 22,
				"username": "alice",
				"password": "secret",
				"method": "slowdns",
				"dnsttNs": "ns.example.com",
				"dnsttPubkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				"dnsttResolver": "1.1.1.1:53",
				"dnsttKcpWindow": 512
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:        "ssh.example.com",
				Port:           22,
				Username:       "alice",
				Password:       "secret",
				UseSlowdns:     true,
				DnsttNs:        "ns.example.com",
				DnsttPubkey:    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				DnsttResolver:  "1.1.1.1:53",
				DnsttKcpWindow: 512,
			},
		},
		{
			// Layer flags win over a legacy "method": payload +
			// TLS layers stay on, "slowdns" is ignored.
			Input: `{
				"address": "ssh.example.com",
				"port": 443,
				"username": "alice",
				"password": "secret",
				"method": "slowdns",
				"usePayload": true,
				"useTls": true,
				"payload": "GET / HTTP/1.1\nHost: [host]\n\n"
			}`,
			Parser: loadJSON(creator),
			Output: &ssh.Config{
				Address:    "ssh.example.com",
				Port:       443,
				Username:   "alice",
				Password:   "secret",
				UsePayload: true,
				UseTls:     true,
				Payload:    "GET / HTTP/1.1\nHost: [host]\n\n",
			},
		},
	})
}

func TestSSHConfigMissingAddress(t *testing.T) {
	config := new(SSHClientConfig)
	if err := json.Unmarshal([]byte(`{"username": "alice", "password": "secret"}`), config); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(); err == nil {
		t.Fatal("expected an error for missing address, got nil")
	}
}

// TestSSHOutboundDetour proves the "ssh" protocol id is registered in
// the outbound JSON config loader: a full outbound detour builds into
// an OutboundHandlerConfig whose proxy settings are the ssh config.
func TestSSHOutboundDetour(t *testing.T) {
	raw := `{
		"protocol": "ssh",
		"tag": "proxy",
		"settings": {
			"address": "ssh.example.com",
			"port": 22,
			"username": "alice",
			"password": "secret"
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
	if handler.Tag != "proxy" {
		t.Fatalf("unexpected tag: %s", handler.Tag)
	}
	if handler.ProxySettings == nil || !strings.Contains(handler.ProxySettings.Type, "xray.proxy.ssh.Config") {
		t.Fatalf("proxy settings are not the ssh config: %+v", handler.ProxySettings)
	}
}
