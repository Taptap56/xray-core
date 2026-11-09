package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/ssh"
	"google.golang.org/protobuf/proto"
)

// SSHClientConfig is the JSON configuration of the "ssh" outbound.
// All fields map 1:1 to proxy/ssh.Config; nothing is hardcoded.
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
	Method          string   `json:"method"`
	Payload         string   `json:"payload"`
	WsPath          string   `json:"wsPath"`
	WsHost          string   `json:"wsHost"`
	Sni             string   `json:"sni"`
	SniVersion      string   `json:"sniVersion"`
	Insecure        bool     `json:"insecure"`
}

// Build implements Buildable.
func (v *SSHClientConfig) Build() (proto.Message, error) {
	if v.Address == nil {
		return nil, errors.New(`SSH settings: "address" is required`)
	}
	if v.Port == 0 {
		v.Port = 22
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
		Method:          v.Method,
		Payload:         v.Payload,
		WsPath:          v.WsPath,
		WsHost:          v.WsHost,
		Sni:             v.Sni,
		SniVersion:      v.SniVersion,
		Insecure:        v.Insecure,
	}
	return config, nil
}
