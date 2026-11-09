package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/dnstt"
	"google.golang.org/protobuf/proto"
)

// DNSTTClientConfig is the JSON configuration of the "dnstt"
// outbound (a dialerProxy carrying connections through one shared
// DNSTT session). All fields map 1:1 to proxy/dnstt.Config; the
// JSON keys reuse the dnstt* names the app already emits for SSH,
// so one settings object serves both outbounds.
type DNSTTClientConfig struct {
	NS         string `json:"dnsttNs"`
	Pubkey     string `json:"dnsttPubkey"`
	Resolver   string `json:"dnsttResolver"`
	KcpWindow  uint32 `json:"dnsttKcpWindow"`
	RecordType string `json:"dnsttRecordType"`
}

// Build implements Buildable.
func (v *DNSTTClientConfig) Build() (proto.Message, error) {
	if v.NS == "" {
		return nil, errors.New(`DNSTT settings: "dnsttNs" is required`)
	}
	config := &dnstt.Config{
		Ns:         v.NS,
		Pubkey:     v.Pubkey,
		Resolver:   v.Resolver,
		KcpWindow:  v.KcpWindow,
		RecordType: v.RecordType,
	}
	return config, nil
}
