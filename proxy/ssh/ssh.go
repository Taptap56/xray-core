// Package ssh implements an SSH outbound for Xray.
//
// It keeps ONE persistent SSH client connection to the configured
// server and opens every outbound TCP connection as an SSH
// direct-tcpip channel on it — the same shape as sing-box/mihomo's
// native SSH outbound. There is no SOCKS listener and no separate
// process: the SSH client runs in-process, inside the core.
//
// When the config carries DNSTT (SlowDNS) settings, the SSH server
// is dialed through a DNSTT session (transport/internet/dnstt)
// instead of a direct TCP dial: the session's streams go to the
// server's fixed port, which must be the SSH port.
//
// The transport method (Config.Method, HTTP Custom style) selects
// how the server is reached: direct TCP (default), a custom payload
// over TCP, WebSocket, WebSocket over TLS, direct TLS with SNI only,
// or the DNSTT dial above. Empty method + DNSTT settings implies
// slowdns, so older SlowDNS profiles keep working.
//
// Limitations (by protocol design, not by implementation):
//   - TCP only. SSH direct-tcpip has no UDP channel, so UDP
//     destinations are rejected. (DNS itself is served by Xray's own
//     DNS outbound, not by this handler.)
//   - Host keys are NOT verified (ssh.InsecureIgnoreHostKey): the
//     injector-style tradeoff — the server is the user's own SSH
//     account, and there is no known-hosts store on the phone. The
//     tunnel still encrypts the traffic; it just does not authenticate
//     the server.
package ssh

import (
	"context"
	"crypto/tls"
	stdnet "net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/dnstt"
)

// sshHandshakeTimeout bounds the DNSTT session establishment +
// SSH handshake. The DNSTT Noise handshake alone takes ~6-7 s.
const sshHandshakeTimeout = 30 * time.Second

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c, err := NewClient(ctx, config.(*Config))
		if err != nil {
			return nil, err
		}
		return c, nil
	}))
}

// Client is an SSH outbound handler.
type Client struct {
	config        *Config
	policyManager policy.Manager

	mu        sync.Mutex
	sshClient *ssh.Client
	dnsttDial *dnstt.Dialer
}

// NewClient creates an SSH outbound handler from its config. It
// validates the settings but does not dial anything yet: the SSH
// connection is established lazily on the first Process call.
func NewClient(ctx context.Context, config *Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("ssh: nil config")
	}
	if strings.TrimSpace(config.Address) == "" {
		return nil, errors.New("ssh: empty server address")
	}
	if strings.TrimSpace(config.Username) == "" {
		return nil, errors.New("ssh: empty username")
	}
	if config.Password == "" && strings.TrimSpace(config.PrivateKey) == "" {
		return nil, errors.New("ssh: either password or private_key must be set")
	}
	method := strings.ToLower(strings.TrimSpace(config.Method))
	switch method {
	case "", methodDirect, methodPayload, methodWS, methodWSTLS, methodTLS, methodSlowDNS:
		// Known methods ("" is direct).
	default:
		return nil, errors.New("ssh: unknown method ", config.Method)
	}
	if method == methodPayload && strings.TrimSpace(config.Payload) == "" {
		return nil, errors.New("ssh: method \"payload\" needs a payload")
	}
	if method == methodSlowDNS && strings.TrimSpace(config.DnsttNs) == "" {
		return nil, errors.New("ssh: method \"slowdns\" needs dnstt_ns")
	}
	if _, _, err := tlsVersionRange(config.SniVersion); err != nil {
		return nil, err
	}
	c := &Client{config: config}
	// The DNSTT dialer is created only when the effective method
	// uses it: explicit "slowdns", or empty method with DNSTT
	// settings (older SlowDNS profiles have no method field). A
	// profile that picks payload/ws/tls keeps stale DNSTT fields
	// without them breaking the client.
	if method == methodSlowDNS || (method == "" && strings.TrimSpace(config.DnsttNs) != "") {
		dialer, err := dnstt.NewDialerWithRecordType(config.DnsttNs, config.DnsttPubkey, config.DnsttResolver, int(config.DnsttKcpWindow), config.DnsttRecordType)
		if err != nil {
			return nil, errors.New("ssh: invalid DNSTT settings").Base(err)
		}
		c.dnsttDial = dialer
	}
	if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
		c.policyManager = pm
		return nil
	}); err != nil {
		return nil, err
	}
	return c, nil
}

// serverAddr returns the SSH server's host:port (default port 22).
func (c *Client) serverAddr() string {
	port := c.config.Port
	if port == 0 {
		port = 22
	}
	return stdnet.JoinHostPort(c.config.Address, net.Port(port).String())
}

// sshClientConfig builds the x/crypto/ssh client config. The password
// / private key are used only here, never logged.
func (c *Client) sshClientConfig() (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		User:            c.config.Username,
		Timeout:         sshHandshakeTimeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if strings.TrimSpace(c.config.PrivateKey) != "" {
		signer, err := ssh.ParsePrivateKey([]byte(c.config.PrivateKey))
		if err != nil {
			return nil, errors.New("ssh: invalid private key").Base(err)
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}
	if c.config.Password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(c.config.Password))
	}
	return cfg, nil
}

// dialTCP dials the SSH server directly (plain TCP) through the
// core dialer, with the same retry as before.
func (c *Client) dialTCP(ctx context.Context, dialer internet.Dialer) (stdnet.Conn, error) {
	dest := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress(c.config.Address),
		Port:    net.Port(c.config.Port),
	}
	if dest.Port == 0 {
		dest.Port = 22
	}
	var transport stdnet.Conn
	if err := retry.ExponentialBackoff(3, 200).On(func() error {
		var err error
		transport, err = dialer.Dial(ctx, dest)
		return err
	}); err != nil {
		return nil, errors.New("ssh: dial server").Base(err)
	}
	return transport, nil
}

// dialTLS dials the SSH server over direct TLS (SNI only, no
// payload, no WebSocket): TCP dial, then a TLS handshake with the
// effective SNI, the insecure toggle and the SNI version.
func (c *Client) dialTLS(ctx context.Context, dialer internet.Dialer) (stdnet.Conn, error) {
	raw, err := c.dialTCP(ctx, dialer)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := buildTLSConfig(c.effectiveSNI(), c.config.SniVersion, c.config.Insecure)
	if err != nil {
		raw.Close()
		return nil, err
	}
	tlsConn := tls.Client(raw, tlsCfg)
	dialCtx, cancel := context.WithTimeout(ctx, sshHandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		raw.Close()
		return nil, errors.New("ssh: TLS handshake with server").Base(err)
	}
	return tlsConn, nil
}

// dialTransport dials the transport to the SSH server according to
// the effective method, and returns the raw connection over which
// the SSH handshake runs. The DNSTT session (when used) is owned by
// the dnstt dialer and shared across re-establishments.
func (c *Client) dialTransport(ctx context.Context, dialer internet.Dialer) (stdnet.Conn, error) {
	switch c.effectiveMethod() {
	case methodSlowDNS:
		dialCtx, cancel := context.WithTimeout(ctx, sshHandshakeTimeout)
		defer cancel()
		transport, err := c.dnsttDial.DialContext(dialCtx, "tcp", c.serverAddr())
		if err != nil {
			return nil, errors.New("ssh: dial server through DNSTT").Base(err)
		}
		return transport, nil
	case methodPayload:
		transport, err := c.dialTCP(ctx, dialer)
		if err != nil {
			return nil, err
		}
		payload := substitutePayload(c.config.Payload, c.config.Address, c.config.Port)
		if _, err := transport.Write([]byte(payload)); err != nil {
			transport.Close()
			return nil, errors.New("ssh: send payload").Base(err)
		}
		return transport, nil
	case methodWS:
		return c.dialWebSocket(ctx, dialer, false)
	case methodWSTLS:
		return c.dialWebSocket(ctx, dialer, true)
	case methodTLS:
		return c.dialTLS(ctx, dialer)
	default: // direct
		return c.dialTCP(ctx, dialer)
	}
}

// getSSHClient returns the live persistent SSH client, establishing
// it first if needed.
func (c *Client) getSSHClient(ctx context.Context, dialer internet.Dialer) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sshClient != nil {
		return c.sshClient, nil
	}
	sshCfg, err := c.sshClientConfig()
	if err != nil {
		return nil, err
	}
	transport, err := c.dialTransport(ctx, dialer)
	if err != nil {
		return nil, err
	}
	conn, chans, reqs, err := ssh.NewClientConn(transport, c.serverAddr(), sshCfg)
	if err != nil {
		transport.Close()
		return nil, errors.New("ssh: handshake with server").Base(err)
	}
	c.sshClient = ssh.NewClient(conn, chans, reqs)
	return c.sshClient, nil
}

// resetClient drops the cached SSH client (e.g. after a channel
// open failed on a dead connection) so the next Process call
// establishes a fresh one. Caller must not hold c.mu.
func (c *Client) resetClient() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sshClient != nil {
		_ = c.sshClient.Close()
		c.sshClient = nil
	}
}

// Close releases the SSH client and the DNSTT dialer.
func (c *Client) Close() error {
	c.resetClient()
	if c.dnsttDial != nil {
		return c.dnsttDial.Close()
	}
	return nil
}

// Process implements proxy.Outbound.Process.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("ssh: target not specified.")
	}
	ob.Name = "ssh"
	ob.CanSpliceCopy = 2
	destination := ob.Target

	if destination.Network == net.Network_UDP {
		// SSH direct-tcpip is TCP-only; there is no UDP channel.
		return errors.New("ssh: UDP is not supported by the SSH outbound")
	}

	client, err := c.getSSHClient(ctx, dialer)
	if err != nil {
		return err
	}
	channel, err := client.DialContext(ctx, "tcp", destination.NetAddr())
	if err != nil {
		// A failed channel open usually means the cached SSH
		// connection is dead; drop it so the next connection retries
		// with a fresh one instead of failing forever.
		c.resetClient()
		return errors.New("ssh: open channel to ", destination).Base(err)
	}
	defer channel.Close()

	p := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
	}, p.Timeouts.ConnectionIdle)

	requestFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(channel), buf.UpdateActivity(timer))
	}
	responseFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(channel), link.Writer, buf.UpdateActivity(timer))
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		return errors.New("ssh: connection ends").Base(err)
	}
	return nil
}
