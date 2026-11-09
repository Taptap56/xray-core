package scenarios

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	sshout "github.com/xtls/xray-core/proxy/ssh"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

// directTCPIPChannelData is the payload of an SSH "direct-tcpip"
// channel open (RFC 4254 §7.2).
type directTCPIPChannelData struct {
	Host           string
	Port           uint32
	OriginatorIP   string
	OriginatorPort uint32
}

// testSSHServer is a minimal in-process SSH server: password auth,
// forwards direct-tcpip channels to the requested destination.
type testSSHServer struct {
	listener net.Listener
	wg       sync.WaitGroup
}

func startTestSSHServer(t *testing.T, username, password string) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	common.Must(err)
	signer, err := ssh.NewSignerFromKey(priv)
	common.Must(err)

	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if conn.User() == username && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("wrong password for %q", conn.User())
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	s := &testSSHServer{listener: ln}
	s.wg.Add(1)
	go s.acceptLoop(config)
	return s
}

func (s *testSSHServer) acceptLoop(config *ssh.ServerConfig) {
	defer s.wg.Done()
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handleConn(raw, config)
	}
}

func (s *testSSHServer) handleConn(raw net.Conn, config *ssh.ServerConfig) {
	defer s.wg.Done()
	defer raw.Close()
	conn, chans, reqs, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		var payload directTCPIPChannelData
		if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
			_ = newChannel.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
			continue
		}
		target := net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port)))
		dst, err := net.Dial("tcp", target)
		if err != nil {
			_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, reqs, err := newChannel.Accept()
		if err != nil {
			dst.Close()
			continue
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			_, _ = io.Copy(dst, ch)
			dst.Close()
			ch.Close()
		}()
		go func() {
			_, _ = io.Copy(ch, dst)
			dst.Close()
			ch.Close()
		}()
	}
}

func (s *testSSHServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *testSSHServer) Close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

// TestSSHOutboundTCP proves the native SSH outbound end to end (no
// DNSTT): a dokodemo inbound rewrites to a TCP echo server, the SSH
// outbound opens a direct-tcpip channel through the in-process SSH
// server, and the bytes come back.
func TestSSHOutboundTCP(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	sshServer := startTestSSHServer(t, "testuser", "testpass")
	defer sshServer.Close()
	sshHost, sshPortStr, err := net.SplitHostPort(sshServer.Addr())
	common.Must(err)
	sshPort, err := strconv.Atoi(sshPortStr)
	common.Must(err)

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
				ProxySettings: serial.ToTypedMessage(&sshout.Config{
					Address:  sshHost,
					Port:     uint32(sshPort),
					Username: "testuser",
					Password: "testpass",
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	if err := testTCPConn(clientPort, 1024, time.Second*2)(); err != nil {
		t.Error(err)
	}
}
