package ssh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	stdnet "net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/dnstt"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// testDialer dials plain TCP to the destination, so the SSH layer
// stack can be exercised without a full core.
type testDialer struct{}

func (testDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	return stdnet.Dial("tcp", dest.NetAddr())
}

func (testDialer) DestIpAddress() stdnet.IP { return nil }

func (testDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

// startEchoServer starts a TCP echo server; returns its address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c stdnet.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// methodTestSSHServer is a minimal in-process SSH server (password
// auth) that forwards direct-tcpip channels to the echo server.
type methodTestSSHServer struct {
	config   *ssh.ServerConfig
	echoAddr string
	wg       sync.WaitGroup
}

func newMethodTestSSHServer(t *testing.T, echoAddr string) *methodTestSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	common.Must(err)
	signer, err := ssh.NewSignerFromKey(priv)
	common.Must(err)
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if conn.User() == "alice" && string(pass) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("wrong password for %q", conn.User())
		},
	}
	config.AddHostKey(signer)
	return &methodTestSSHServer{config: config, echoAddr: echoAddr}
}

// serve runs the SSH handshake and channel forwarding over raw.
func (s *methodTestSSHServer) serve(raw stdnet.Conn) {
	defer s.wg.Done()
	defer raw.Close()
	conn, chans, reqs, err := ssh.NewServerConn(raw, s.config)
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
		var payload struct {
			Host           string
			Port           uint32
			OriginatorIP   string
			OriginatorPort uint32
		}
		if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
			_ = newChannel.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
			continue
		}
		dst, err := stdnet.Dial("tcp", stdnet.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port))))
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

// serveListener accepts TCP connections on ln, applies wrap to each
// (nil = identity), and serves SSH over them. A failed Accept does
// NOT stop serving — only a closed listener does. (The SNI-only
// CONNECT knock hits a TLS listener as a plaintext connection, so
// its Accept fails the TLS handshake; the real dial follows on the
// next Accept and must still be served.)
func (s *methodTestSSHServer) serveListener(t *testing.T, ln stdnet.Listener, wrap func(stdnet.Conn) (stdnet.Conn, error)) {
	t.Helper()
	t.Cleanup(func() { ln.Close() })
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			raw, err := ln.Accept()
			if err != nil {
				if errors.Is(err, stdnet.ErrClosed) {
					return
				}
				continue
			}
			s.wg.Add(1)
			go func(raw stdnet.Conn) {
				if wrap != nil {
					wrapped, err := wrap(raw)
					if err != nil {
						raw.Close()
						s.wg.Done()
						return
					}
					raw = wrapped
				}
				s.serve(raw)
			}(raw)
		}
	}()
}

// dialSSHAndEchoErr dials the SSH server through the client's layer
// stack, opens a direct-tcpip channel to the echo server, and
// verifies the echo. It proves the transport + SSH handshake +
// channel all work end to end.
func dialSSHAndEchoErr(t *testing.T, c *Client, echoAddr string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport, err := c.dialTransport(ctx, testDialer{})
	if err != nil {
		return fmt.Errorf("dialTransport: %w", err)
	}
	defer transport.Close()
	sshCfg, err := c.sshClientConfig()
	if err != nil {
		return fmt.Errorf("sshClientConfig: %w", err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(transport, c.serverAddr(), sshCfg)
	if err != nil {
		return fmt.Errorf("SSH handshake: %w", err)
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	channel, err := client.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		return fmt.Errorf("open channel: %w", err)
	}
	defer channel.Close()
	if _, err := channel.Write([]byte("hello-ssh")); err != nil {
		return fmt.Errorf("write channel: %w", err)
	}
	buf := make([]byte, len("hello-ssh"))
	if _, err := io.ReadFull(channel, buf); err != nil {
		return fmt.Errorf("read channel: %w", err)
	}
	if string(buf) != "hello-ssh" {
		return fmt.Errorf("echo = %q, want %q", string(buf), "hello-ssh")
	}
	return nil
}

func dialSSHAndEcho(t *testing.T, c *Client, echoAddr string) {
	t.Helper()
	if err := dialSSHAndEchoErr(t, c, echoAddr); err != nil {
		t.Fatal(err)
	}
}

func sshClientFor(t *testing.T, host string, port int) *Client {
	t.Helper()
	return &Client{config: &Config{
		Address:  host,
		Port:     uint32(port),
		Username: "alice",
		Password: "secret",
	}}
}

// readPayloadWrap returns a wrap that reads the HTTP-style payload
// up to the end of the headers, verifies it equals want, and keeps
// the buffered bytes for whatever follows (SSH or TLS handshake).
func readPayloadWrap(t *testing.T, want string) func(stdnet.Conn) (stdnet.Conn, error) {
	t.Helper()
	return func(raw stdnet.Conn) (stdnet.Conn, error) {
		r := bufio.NewReader(raw)
		var sb strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return nil, err
			}
			sb.WriteString(line)
			if sb.String() == want {
				break
			}
			if sb.Len() > len(want)+64 {
				return nil, fmt.Errorf("payload mismatch: got %q", sb.String())
			}
		}
		return &bufferedConn{Conn: raw, r: r}, nil
	}
}

// TestDialDirectEndToEnd is the baseline: plain TCP dial + SSH, no
// layers on.
func TestDialDirectEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.serveListener(t, ln, nil)
	addr := ln.Addr().(*stdnet.TCPAddr)
	dialSSHAndEcho(t, sshClientFor(t, "127.0.0.1", addr.Port), echoAddr)
}

// TestDialPayloadEndToEnd proves the payload layer: the server reads
// the HTTP-style payload first (and checks its content), then the
// SSH handshake follows on the same connection.
func TestDialPayloadEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*stdnet.TCPAddr)
	wantPayload := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Port: " + strconv.Itoa(addr.Port) + "\r\n\r\n"
	srv.serveListener(t, ln, readPayloadWrap(t, wantPayload))
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UsePayload = true
	c.config.Payload = "GET / HTTP/1.1\nHost: [host]\nX-Port: [port]\n\n"
	dialSSHAndEcho(t, c, echoAddr)
}

// TestDialEnhancedEndToEnd proves the chain reads the server's
// HTTP response to the payload before the handshake. The response
// here carries one header line longer than 255 bytes on purpose:
// x/crypto/ssh tolerates leading non-SSH lines, but a single line
// over 255 bytes (maxVersionStringBytes) overflows its version
// reader, so a client that does NOT consume the response fails
// the handshake, while one that does handshakes cleanly. The chain
// reads one response per payload request whenever a payload is
// sent — UseEnhanced and plain UsePayload behave the same here —
// so both clients must succeed.
func TestDialEnhancedEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*stdnet.TCPAddr)
	wantPayload := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
	var resp strings.Builder
	resp.WriteString("HTTP/1.1 200 OK\r\n")
	resp.WriteString("X-Long: " + strings.Repeat("a", 300) + "\r\n")
	resp.WriteString("\r\n")
	wrap := func(raw stdnet.Conn) (stdnet.Conn, error) {
		conn, err := readPayloadWrap(t, wantPayload)(raw)
		if err != nil {
			return nil, err
		}
		if _, err := conn.Write([]byte(resp.String())); err != nil {
			return nil, err
		}
		return conn, nil
	}
	srv.serveListener(t, ln, wrap)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UseEnhanced = true
	c.config.Payload = "GET / HTTP/1.1\nHost: [host]\n\n"
	dialSSHAndEcho(t, c, echoAddr)

	// Plain payload against the same server must ALSO succeed: the
	// chain reads the response for any payload, not only when
	// UseEnhanced is set.
	c2 := sshClientFor(t, "127.0.0.1", addr.Port)
	c2.config.UsePayload = true
	c2.config.Payload = "GET / HTTP/1.1\nHost: [host]\n\n"
	dialSSHAndEcho(t, c2, echoAddr)
}

// TestDialEnhancedAgainstRealSSHServer proves the enhanced layer is
// best-effort: a real SSH server never sends HTTP response headers —
// it answers the payload with its SSH version banner ("SSH-2.0-…")
// and waits for the client's. The enhanced client must not hang
// waiting for a blank line that never comes, and must not lose the
// banner: it reads the first line, sees it is not HTTP, and replays
// it to the SSH handshake (the server writes its banner before
// reading the client's version, so consuming it would leave the
// handshake staring at the binary key-exchange packet).
func TestDialEnhancedAgainstRealSSHServer(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// No wrap: a real sshd, which sends its banner and waits.
	srv.serveListener(t, ln, nil)
	addr := ln.Addr().(*stdnet.TCPAddr)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UseEnhanced = true
	c.config.Payload = "GET / HTTP/1.1\nHost: [host]\n\n"
	dialSSHAndEcho(t, c, echoAddr)
}

// selfSignedCert generates a self-signed TLS cert for 127.0.0.1.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"127.0.0.1"},
		IPAddresses:  []stdnet.IP{stdnet.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestDialTLSEndToEnd proves the TLS layer: direct TLS (SNI only)
// to the SSH server, with insecure skip-verify against a self-signed
// cert, and the SNI version pinned to TLS 1.2.
func TestDialTLSEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv.serveListener(t, ln, nil)
	addr := ln.Addr().(*stdnet.TCPAddr)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UseTls = true
	c.config.Sni = "127.0.0.1"
	c.config.SniVersion = "tls1.2"
	c.config.Insecure = true
	dialSSHAndEcho(t, c, echoAddr)
}

// TestDialTlsPayloadEndToEnd proves the chain order: TLS first,
// then the payload inside the TLS tunnel, then SSH. The server
// does the TLS handshake first, reads the payload (inside TLS),
// then SSH — the same order the client stacks. (The old order,
// payload-then-TLS, sent the payload in plaintext before the
// handshake; the chain sends it inside TLS.)
func TestDialTlsPayloadEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	cert := selfSignedCert(t)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*stdnet.TCPAddr)
	wantPayload := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
	wrap := func(raw stdnet.Conn) (stdnet.Conn, error) {
		tlsConn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		return readPayloadWrap(t, wantPayload)(tlsConn)
	}
	srv.serveListener(t, ln, wrap)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UsePayload = true
	c.config.Payload = "GET / HTTP/1.1\nHost: [host]\n\n"
	c.config.UseTls = true
	c.config.Sni = "127.0.0.1"
	c.config.SniVersion = "tls1.2"
	c.config.Insecure = true
	dialSSHAndEcho(t, c, echoAddr)
}

// TestDialProxySlowDnsOrder proves the documented order: when both
// the remote proxy and the slowdns layer are on, the proxy target
// dial goes through the DNSTT tunnel — not direct TCP. The DNSTT
// resolver here is deliberately invalid (port 99999), so the
// tunnel fails fast at parse time; the error must mention DNSTT,
// which only happens if the proxy dial took the DNSTT branch.
// (CONNECT is gone — the chain dials the proxy as a plain target —
// but the DNSTT-vs-direct choice for that dial is unchanged.)
func TestDialProxySlowDnsOrder(t *testing.T) {
	// Built directly (NewClient needs a core context for the policy
	// manager); the DNSTT dialer is created the same way NewClient
	// does it.
	cfg := &Config{
		Address:       "127.0.0.1",
		Port:          22,
		Username:      "alice",
		Password:      "secret",
		UseSlowdns:    true,
		DnsttNs:       "ns.example.com",
		DnsttPubkey:   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		DnsttResolver: "1.1.1.1:99999",
		RemoteProxy:   "127.0.0.1:3128",
	}
	client := &Client{config: cfg}
	var err error
	client.dnsttDial, err = dnstt.NewDialerWithRecordType(cfg.DnsttNs, cfg.DnsttPubkey, cfg.DnsttResolver, int(cfg.DnsttKcpWindow), cfg.DnsttRecordType)
	if err != nil {
		t.Fatalf("NewDialerWithRecordType: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.dialTransport(ctx, testDialer{})
	if err == nil {
		t.Fatal("expected a DNSTT error, got nil")
	}
	if !strings.Contains(err.Error(), "DNSTT") {
		t.Errorf("error = %v, want it to mention DNSTT (proxy through tunnel)", err)
	}
}

func TestParseRemoteProxy(t *testing.T) {
	cases := []struct {
		in       string
		user     string
		pass     string
		host     string
		port     int
		expectOK bool
	}{
		{"127.0.0.1:3128", "", "", "127.0.0.1", 3128, true},
		{"proxy.example.com:8080", "", "", "proxy.example.com", 8080, true},
		{"alice:secret@127.0.0.1:3128", "alice", "secret", "127.0.0.1", 3128, true},
		{"alice@127.0.0.1:3128", "alice", "", "127.0.0.1", 3128, true},
		{"[2001:db8::1]:80", "", "", "2001:db8::1", 80, true},
		{"user:pass@[2001:db8::1]:80", "user", "pass", "2001:db8::1", 80, true},
		{" 127.0.0.1:3128 ", "", "", "127.0.0.1", 3128, true}, // trimmed
		{"", "", "", "", 0, false},
		{"127.0.0.1", "", "", "", 0, false},       // no port
		{"127.0.0.1:0", "", "", "", 0, false},     // port 0
		{"127.0.0.1:99999", "", "", "", 0, false}, // port too big
		{"127.0.0.1:abc", "", "", "", 0, false},   // non-numeric port
		{":3128", "", "", "", 0, false},           // empty host
	}
	for _, tc := range cases {
		user, pass, host, port, err := parseRemoteProxy(tc.in)
		if tc.expectOK {
			if err != nil {
				t.Errorf("parseRemoteProxy(%q): unexpected error: %v", tc.in, err)
				continue
			}
			if user != tc.user || pass != tc.pass || host != tc.host || port != tc.port {
				t.Errorf("parseRemoteProxy(%q) = (%q, %q, %q, %d), want (%q, %q, %q, %d)",
					tc.in, user, pass, host, port, tc.user, tc.pass, tc.host, tc.port)
			}
		} else if err == nil {
			t.Errorf("parseRemoteProxy(%q): expected error, got (%q, %q, %q, %d)", tc.in, user, pass, host, port)
		}
	}
}

func TestReadChainResponse(t *testing.T) {
	// HTTP response: the status line + headers are consumed, and
	// the bytes after the blank line stay buffered.
	br := bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nX-Test: 1\r\n\r\nSSH-2.0-test"))
	status, err := readChainResponse(br)
	if err != nil {
		t.Fatal(err)
	}
	if status != "HTTP/1.1 200 OK" {
		t.Errorf("status = %q, want %q", status, "HTTP/1.1 200 OK")
	}
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "SSH-2.0-test" {
		t.Errorf("bytes after headers = %q, want %q", string(rest), "SSH-2.0-test")
	}

	// Non-HTTP first line (a real SSH server's banner): NOT
	// consumed, no error, status "" — the bytes stay buffered for
	// framing detection and the SSH handshake.
	br = bufio.NewReader(strings.NewReader("SSH-2.0-test\r\nmore"))
	status, err = readChainResponse(br)
	if err != nil {
		t.Fatal(err)
	}
	if status != "" {
		t.Errorf("non-HTTP status = %q, want empty", status)
	}
	rest, err = io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "SSH-2.0-test\r\nmore" {
		t.Errorf("banner bytes = %q, want %q", string(rest), "SSH-2.0-test\r\nmore")
	}
}

func TestValidateConfig(t *testing.T) {
	// Fresh Config per case: copying a Config copies its embedded
	// protoimpl.MessageState (a Mutex), which go vet flags.
	valid := func() *Config {
		return &Config{Address: "example.com", Port: 22, Username: "alice", Password: "secret"}
	}
	// Payload layer without a payload is rejected.
	cfg := valid()
	cfg.UsePayload = true
	if err := validateConfig(cfg); err == nil {
		t.Error("payload layer without payload: expected error, got nil")
	}
	// Enhanced layer without a payload is rejected too.
	cfg = valid()
	cfg.UseEnhanced = true
	if err := validateConfig(cfg); err == nil {
		t.Error("enhanced layer without payload: expected error, got nil")
	}
	// SlowDNS layer without an NS is rejected.
	cfg = valid()
	cfg.UseSlowdns = true
	if err := validateConfig(cfg); err == nil {
		t.Error("slowdns layer without NS: expected error, got nil")
	}
	// A malformed remote proxy is rejected.
	cfg = valid()
	cfg.RemoteProxy = "127.0.0.1"
	if err := validateConfig(cfg); err == nil {
		t.Error("remote proxy without port: expected error, got nil")
	}
	// A bad SNI version is still rejected.
	cfg = valid()
	cfg.SniVersion = "tls9"
	if err := validateConfig(cfg); err == nil {
		t.Error("bad SNI version: expected error, got nil")
	}
	// No layers + no auth credentials is rejected (as before).
	cfg = valid()
	cfg.Username = ""
	cfg.Password = ""
	if err := validateConfig(cfg); err == nil {
		t.Error("no username/password/private key: expected error, got nil")
	}
	// A valid layered config passes.
	cfg = valid()
	cfg.UsePayload = true
	cfg.Payload = "GET / HTTP/1.1\nHost: [host]\n\n"
	cfg.UseTls = true
	cfg.RemoteProxy = "127.0.0.1:3128"
	if err := validateConfig(cfg); err != nil {
		t.Errorf("valid layered config: unexpected error: %v", err)
	}
}

// --- Cloudflare replay test (fake proxy) ---

// readHTTPRequest reads one HTTP request (lines up to the blank
// line) and returns the raw request text.
func readHTTPRequest(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		sb.WriteString(line)
		if strings.TrimRight(line, "\r\n") == "" {
			return sb.String(), nil
		}
		if sb.Len() > 64*1024 {
			return "", fmt.Errorf("HTTP request too long")
		}
	}
}

// cloudflareProxy is a fake stand-in for Cloudflare's edge
// (104.17.3.81:80), replaying the exact sequence the parent proved
// by sending the user's HC payload at it: it REJECTS a CONNECT with
// 400 (like Cloudflare), but answers a payload's HEAD request with
// 301 and its BMOVE/WS-upgrade request with 101, then speaks raw
// SSH on the same connection.
type cloudflareProxy struct {
	ln   stdnet.Listener
	srv  *methodTestSSHServer
	mu   sync.Mutex
	req1 string // first request seen (HEAD)
	req2 string // second request seen (BMOVE)
}

func startCloudflareProxy(t *testing.T, srv *methodTestSSHServer) *cloudflareProxy {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &cloudflareProxy{ln: ln, srv: srv}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(raw)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *cloudflareProxy) handle(raw stdnet.Conn) {
	defer raw.Close()
	br := bufio.NewReader(raw)
	req1, err := readHTTPRequest(br)
	if err != nil {
		return
	}
	if strings.HasPrefix(req1, "CONNECT") {
		// CONNECT is rejected with 400, like Cloudflare.
		_, _ = io.WriteString(raw, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	p.mu.Lock()
	p.req1 = req1
	p.mu.Unlock()
	_, _ = io.WriteString(raw, "HTTP/1.1 301 Moved Permanently\r\nLocation: https://edu.ruangguru.com/\r\nContent-Length: 0\r\n\r\n")
	req2, err := readHTTPRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.req2 = req2
	p.mu.Unlock()
	_, _ = io.WriteString(raw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	// Then the raw SSH server speaks on the same connection.
	p.srv.wg.Add(1)
	p.srv.serve(&bufferedConn{Conn: raw, r: br})
}

// TestDialChainCloudflareReplayEndToEnd replays the user's failing
// config against a fake Cloudflare edge: Payload + Enhanced, remote
// proxy = the fake edge, payload = HEAD edu.ruangguru.com + BMOVE
// Upgrade: websocket. The edge answers 301 then 101 then a raw SSH
// banner — the client must connect and echo. Against the OLD code
// this FAILS: the old dialProxy sends CONNECT, which the edge
// rejects with 400 ("remote proxy CONNECT failed: 400").
func TestDialChainCloudflareReplayEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	proxy := startCloudflareProxy(t, srv)
	addr := proxy.ln.Addr().(*stdnet.TCPAddr)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UsePayload = true
	c.config.UseEnhanced = true
	c.config.RemoteProxy = proxy.ln.Addr().String()
	c.config.Payload = "HEAD / HTTP/1.1[crlf]Host: edu.ruangguru.com:80[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]BMOVE / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
	dialSSHAndEcho(t, c, echoAddr)
	// The edge must have seen the payload as two requests (HEAD
	// then BMOVE), not a CONNECT — and the WS handshake headers
	// must have been added to the upgrade request.
	proxy.mu.Lock()
	req1, req2 := proxy.req1, proxy.req2
	proxy.mu.Unlock()
	if !strings.Contains(req1, "HEAD") || !strings.Contains(req1, "edu.ruangguru.com") {
		t.Errorf("request 1 = %q, want a HEAD to edu.ruangguru.com", req1)
	}
	if !strings.Contains(req2, "BMOVE") || !strings.Contains(req2, "Upgrade: websocket") {
		t.Errorf("request 2 = %q, want a BMOVE with Upgrade: websocket", req2)
	}
	if !strings.Contains(strings.ToLower(req2), "sec-websocket-key") {
		t.Errorf("request 2 = %q, want Sec-WebSocket-Key added", req2)
	}
}

// --- Chain WS framing test (server-side WS) ---

// writeWSFrameServer writes one unmasked WS frame (server ->
// client): FIN + opcode, no mask bit.
func writeWSFrameServer(w io.Writer, op byte, payload []byte) error {
	var hdr [10]byte
	hdr[0] = 0x80 | op // FIN + opcode
	n := len(payload)
	var hlen int
	switch {
	case n < 126:
		hdr[1] = byte(n)
		hlen = 2
	case n < 65536:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hlen = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		hlen = 10
	}
	if _, err := w.Write(hdr[:hlen]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// wsServerConn is a server-side WebSocket connection for tests: it
// reads masked binary frames from the client and writes unmasked
// binary frames to the client.
type wsServerConn struct {
	stdnet.Conn
	rbuf []byte
	roff int
}

func (w *wsServerConn) Read(b []byte) (int, error) {
	if w.roff < len(w.rbuf) {
		n := copy(b, w.rbuf[w.roff:])
		w.roff += n
		if w.roff >= len(w.rbuf) {
			w.rbuf = nil
			w.roff = 0
		}
		return n, nil
	}
	for {
		op, payload, err := readWSFrame(w.Conn)
		if err != nil {
			return 0, err
		}
		switch op {
		case 0x9: // ping -> pong
			_ = writeWSFrameServer(w.Conn, 0xA, payload)
			continue
		case 0x8: // close
			return 0, io.EOF
		case 0x2, 0x1, 0x0: // binary/text/continuation
			w.rbuf = append(w.rbuf, payload...)
			n := copy(b, w.rbuf)
			w.roff = n
			if w.roff >= len(w.rbuf) {
				w.rbuf = nil
				w.roff = 0
			}
			return n, nil
		default:
			continue
		}
	}
}

func (w *wsServerConn) Write(b []byte) (int, error) {
	if err := writeWSFrameServer(w.Conn, 0x2, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// TestDialChainWSFramingEndToEnd proves the chain's WS mode: the
// server answers the WS upgrade with 101, then speaks SSH wrapped
// in WS frames (banner + handshake), and the client must connect
// and echo through the framing. This exercises wsConn (manual
// framing) and the framing detection (0x81/0x82 -> WS).
func TestDialChainWSFramingEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*stdnet.TCPAddr)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw stdnet.Conn) {
				defer raw.Close()
				br := bufio.NewReader(raw)
				// Read the WS upgrade request (until the blank
				// line), answer 101, then serve SSH over WS
				// frames.
				if _, err := readHTTPRequest(br); err != nil {
					return
				}
				if _, err := io.WriteString(raw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
					return
				}
				srv.wg.Add(1)
				srv.serve(&wsServerConn{Conn: &bufferedConn{Conn: raw, r: br}})
			}(raw)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UsePayload = true
	c.config.UseEnhanced = true
	c.config.Payload = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
	dialSSHAndEcho(t, c, echoAddr)
}

// TestDialChainStatusRejection proves the raw-mode status rule: a
// non-WS payload answered with a non-2xx/1xx status (and no server
// data after it) fails the dial with "proxy rejected payload".
// The server answers 403 and closes; the client must not fall
// through to the SSH handshake on a rejected proxy.
func TestDialChainStatusRejection(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*stdnet.TCPAddr)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw stdnet.Conn) {
				defer raw.Close()
				br := bufio.NewReader(raw)
				if _, err := readHTTPRequest(br); err != nil {
					return
				}
				_, _ = io.WriteString(raw, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			}(raw)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	_ = srv
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UsePayload = true
	c.config.Payload = "GET / HTTP/1.1\nHost: [host]\n\n"
	err = dialSSHAndEchoErr(t, c, echoAddr)
	if err == nil {
		t.Fatal("expected a proxy-rejected-payload error, got success")
	}
	if !strings.Contains(err.Error(), "proxy rejected payload") {
		t.Errorf("error = %v, want it to mention proxy rejected payload", err)
	}
}

// --- CONNECT knock test ---

// knockRecordingServer is a fake SSH server that records whether it
// received a Simple-Injector-style CONNECT knock (a plain TCP
// connection that sends "CONNECT host:port HTTP/1.0" and closes)
// before the real TLS+SSH dial arrives. The knock and the main dial
// go to the same address, so the server sniffs the first byte of
// each connection: 'C' = knock, 0x16 = TLS ClientHello.
type knockRecordingServer struct {
	ln      stdnet.Listener
	srv     *methodTestSSHServer
	tlsConf *tls.Config
	knockCh chan string // receives the knock request line, if any
}

func startKnockRecordingServer(t *testing.T, srv *methodTestSSHServer, cert tls.Certificate) *knockRecordingServer {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &knockRecordingServer{
		ln:      ln,
		srv:     srv,
		tlsConf: &tls.Config{Certificates: []tls.Certificate{cert}},
		knockCh: make(chan string, 1),
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(raw)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *knockRecordingServer) handle(raw stdnet.Conn) {
	defer raw.Close()
	br := bufio.NewReader(raw)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 'C' {
		// CONNECT knock: record the request line, close.
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		select {
		case s.knockCh <- strings.TrimSpace(line):
		default:
		}
		return
	}
	// TLS ClientHello: TLS handshake, then SSH.
	tlsConn := tls.Server(&bufferedConn{Conn: raw, r: br}, s.tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	s.srv.wg.Add(1)
	s.srv.serve(tlsConn)
}

// TestDialChainConnectKnockEndToEnd proves the SNI-only knock: TLS
// on, empty payload, no proxy. The client must send a plain
// CONNECT knock on a separate socket BEFORE the TLS dial, and the
// TLS+SSH dial must still succeed afterwards.
func TestDialChainConnectKnockEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	cert := selfSignedCert(t)
	ksrv := startKnockRecordingServer(t, srv, cert)
	addr := ksrv.ln.Addr().(*stdnet.TCPAddr)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UseTls = true
	c.config.Sni = "127.0.0.1"
	c.config.SniVersion = "tls1.2"
	c.config.Insecure = true
	dialSSHAndEcho(t, c, echoAddr)
	// The knock must have arrived (CONNECT host:port HTTP/1.0).
	select {
	case line := <-ksrv.knockCh:
		want := "CONNECT 127.0.0.1:" + strconv.Itoa(addr.Port) + " HTTP/1.0"
		if line != want {
			t.Errorf("knock line = %q, want %q", line, want)
		}
	case <-time.After(5 * time.Second):
		t.Error("no CONNECT knock received")
	}
}

// TestDialChainTLSFallbackToPlainEndToEnd proves the TLS Auto
// fallback: TLS on, sni_version default (auto), no payload, and a
// PLAIN SSH server (no TLS). The TLS handshake fails fast (the
// server answers with an SSH banner, not a ServerHello), so the
// chain re-dials plain TCP and connects.
func TestDialChainTLSFallbackToPlainEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.serveListener(t, ln, nil)
	addr := ln.Addr().(*stdnet.TCPAddr)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UseTls = true
	c.config.Sni = "127.0.0.1"
	c.config.SniVersion = "" // default = auto: fallback allowed
	c.config.Insecure = true
	dialSSHAndEcho(t, c, echoAddr)
}

// TestDialChainTLSForcedNoFallbackEndToEnd proves the fallback does
// NOT apply when the SNI version is forced: TLS on, sni_version
// tls1.2, no payload, and a PLAIN SSH server. The TLS handshake
// fails and the dial fails as usual — it must not silently turn
// plain.
func TestDialChainTLSForcedNoFallbackEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.serveListener(t, ln, nil)
	addr := ln.Addr().(*stdnet.TCPAddr)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	c.config.UseTls = true
	c.config.Sni = "127.0.0.1"
	c.config.SniVersion = "tls1.2" // forced: no fallback
	c.config.Insecure = true
	err = dialSSHAndEchoErr(t, c, echoAddr)
	if err == nil {
		t.Fatal("expected a TLS handshake error, got success")
	}
	if !strings.Contains(err.Error(), "TLS") {
		t.Errorf("error = %v, want it to mention TLS", err)
	}
}
