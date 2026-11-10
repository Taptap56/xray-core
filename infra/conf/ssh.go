package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/ssh"
	"google.golang.org/protobuf/proto"
)

// SSHClientConfig is the JSON configuration of the "ssh" outbound.
// All fields map 1:1 to proxy/ssh.Config, except Method, which is a
// legacy single transport method migrated to the layer flags when
// no layer flag is set. Nothing is hardcoded.
type SSHClientConfig struct {
	Address         *Address `json:"address"`
	Port            uint16   `json:"port"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	PrivateKey      string   `json:"privateKey"`
	DnsttNS         string   `json:"dnsttNs"`
	DnsttPubkey     string   `json:"dnsttPubkey"`
	DnsttResolver   string   `json:"dnsttResolver"`
	DnsttKcpWindow  uint32   `json:"dnsttKcpWindow"`
	DnsttRecordType string   `json:"dnsttRecordType"`
	Payload         string   `json:"payload"`
	Sni             string   `json:"sni"`
	SniVersion      string   `json:"sniVersion"`
	Insecure        bool     `json:"insecure"`
	UsePayload      bool     `json:"usePayload"`
	UseEnhanced     bool     `json:"useEnhanced"`
	UseTls          bool     `json:"useTls"`
	UseSlowdns      bool     `json:"useSlowdns"`
	RemoteProxy     string   `json:"remoteProxy"`
	// Method is the legacy single transport method ("", "direct",
	// "payload", "ws", "ws-tls", "tls", "slowdns"). It is migrated
	// to the layer flags below when no layer flag is set; "ws" and
	// "ws-tls" map to direct (the WS dial was removed — HTTP Custom
	// has no WS transport for SSH, a WebSocket upgrade is sent as a
	// payload instead). Layer flags always win over Method.
	Method string `json:"method"`
}

// Build implements Buildable.
func (v *SSHClientConfig) Build() (proto.Message, error) {
	if v.Address == nil {
		return nil, errors.New(`SSH settings: "address" is required`)
	}
	if v.Port == 0 {
		v.Port = 22
	}
	usePayload, useEnhanced, useTls, useSlowdns := v.UsePayload, v.UseEnhanced, v.UseTls, v.UseSlowdns
	if !usePayload && !useEnhanced && !useTls && !useSlowdns {
		switch strings.ToLower(strings.TrimSpace(v.Method)) {
		case "", "direct":
		case "payload":
			usePayload = true
		case "tls":
			useTls = true
		case "slowdns":
			useSlowdns = true
		case "ws", "ws-tls":
			// WS dial removed: a legacy WS config imports as direct.
		default:
			return nil, errors.New(`SSH settings: unknown method `, v.Method)
		}
	}
	config := &ssh.Config{
		Address:         v.Address.String(),
		Port:            uint32(v.Port),
		Username:        v.Username,
		Password:        v.Password,
		PrivateKey:      v.PrivateKey,
		DnsttNs:         v.DnsttNS,
		DnsttPubkey:     v.DnsttPubkey,
		DnsttResolver:   v.DnsttResolver,
		DnsttKcpWindow:  v.DnsttKcpWindow,
		DnsttRecordType: v.DnsttRecordType,
		Payload:         v.Payload,
		Sni:             v.Sni,
		SniVersion:      v.SniVersion,
		Insecure:        v.Insecure,
		UsePayload:      usePayload,
		UseEnhanced:     useEnhanced,
		UseTls:          useTls,
		UseSlowdns:      useSlowdns,
		RemoteProxy:     v.RemoteProxy,
	}
	return config, nil
}
