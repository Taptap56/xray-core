package scenarios

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dnstt"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

// TestDNSTTOutboundStarts proves the native DNSTT outbound loads in
// a full core: a dokodemo inbound + a DNSTT outbound (dead NS, never
// dialed) starts and stops cleanly. It does not prove traffic flows
// through the tunnel — that needs a live DNSTT server, which only
// exists on the user's phone.
func TestDNSTTOutboundStarts(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(clientPort)}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  xnet.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []xnet.Network{xnet.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "dnstt",
				ProxySettings: serial.ToTypedMessage(&dnstt.Config{
					Ns:         "ns.example.invalid",
					Pubkey:     strings.Repeat("01", 32),
					Resolver:   "1.1.1.1:53",
					KcpWindow:  512,
					RecordType: "null",
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)
}
