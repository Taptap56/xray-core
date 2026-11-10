package ssh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
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
// (nil = identity), and serves SSH over them.
func (s *methodTestSSHServer) serveListener(t *testing.T, ln stdnet.Listener, wrap func(stdnet.Conn) (stdnet.Conn, error)) {
	t.Helper()
	t.Cleanup(func() { ln.Close() })
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
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

// TestDialEnhancedEndToEnd proves the enhanced layer: the server
// reads the payload, answers with HTTP response headers, and only
// then does the SSH handshake. The client must wait for and consume
// the response before the handshake. The response here carries one
// header line longer than 255 bytes on purpose: x/crypto/ssh
// tolerates leading non-SSH lines, but a single line over 255
// bytes (maxVersionStringBytes) overflows its version reader, so a
// plain-payload client against this server fails the handshake,
// while the enhanced client — which consumed the response first —
// handshakes cleanly.
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

	// Control: a plain-payload client against the same server must
	// FAIL — it does not consume the response, so the >255-byte
	// header line overflows the SSH version reader.
	c2 := sshClientFor(t, "127.0.0.1", addr.Port)
	c2.config.UsePayload = true
	c2.config.Payload = "GET / HTTP/1.1\nHost: [host]\n\n"
	if err := dialSSHAndEchoErr(t, c2, echoAddr); err == nil {
		t.Error("plain payload against an enhanced server: expected SSH handshake failure, got success")
	}
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

// TestDialPayloadTlsEndToEnd proves layer stacking: payload under
// TLS. The server reads the plaintext payload first, then does the
// TLS handshake, then SSH — the same order the client stacks.
func TestDialPayloadTlsEndToEnd(t *testing.T) {
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
		conn, err := readPayloadWrap(t, wantPayload)(raw)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		return tlsConn, nil
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

// connectProxy is a minimal HTTP CONNECT proxy: it records the
// request line and headers, dials the target, answers 200, then
// splices the two connections.
type connectProxy struct {
	ln         stdnet.Listener
	request    string // CONNECT request line
	authHeader string // Proxy-Authorization header, if any
}

func startConnectProxy(t *testing.T, targetAddr string) *connectProxy {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &connectProxy{ln: ln}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw stdnet.Conn) {
				defer raw.Close()
				r := bufio.NewReader(raw)
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				p.request = strings.TrimSpace(line)
				for {
					h, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(h) == "" {
						break
					}
					if strings.HasPrefix(strings.ToLower(h), "proxy-authorization:") {
						p.authHeader = strings.TrimSpace(h[len("proxy-authorization:"):])
					}
				}
				target, err := stdnet.Dial("tcp", targetAddr)
				if err != nil {
					return
				}
				defer target.Close()
				if _, err := raw.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					return
				}
				client := &bufferedConn{Conn: raw, r: r}
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = io.Copy(target, client)
					target.Close()
				}()
				go func() {
					defer wg.Done()
					_, _ = io.Copy(client, target)
					raw.Close()
				}()
				wg.Wait()
			}(raw)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

// TestDialProxyEndToEnd proves the remote proxy layer: the client
// CONNECTs through the proxy to the SSH server, and SSH runs over
// the tunnel.
func TestDialProxyEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.serveListener(t, ln, nil)
	sshAddr := ln.Addr().(*stdnet.TCPAddr)
	proxy := startConnectProxy(t, ln.Addr().String())
	c := sshClientFor(t, "127.0.0.1", sshAddr.Port)
	c.config.RemoteProxy = proxy.ln.Addr().String()
	dialSSHAndEcho(t, c, echoAddr)
	wantReq := "CONNECT 127.0.0.1:" + strconv.Itoa(sshAddr.Port) + " HTTP/1.1"
	if proxy.request != wantReq {
		t.Errorf("CONNECT request = %q, want %q", proxy.request, wantReq)
	}
	if proxy.authHeader != "" {
		t.Errorf("Proxy-Authorization = %q, want none", proxy.authHeader)
	}
}

// TestDialProxyAuthEndToEnd proves the remote proxy layer sends
// Proxy-Authorization (Basic) when user:pass@ is given.
func TestDialProxyAuthEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.serveListener(t, ln, nil)
	sshAddr := ln.Addr().(*stdnet.TCPAddr)
	proxy := startConnectProxy(t, ln.Addr().String())
	c := sshClientFor(t, "127.0.0.1", sshAddr.Port)
	c.config.RemoteProxy = "alice:secret@" + proxy.ln.Addr().String()
	dialSSHAndEcho(t, c, echoAddr)
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if proxy.authHeader != wantAuth {
		t.Errorf("Proxy-Authorization = %q, want %q", proxy.authHeader, wantAuth)
	}
}

// TestDialProxySlowDnsOrder proves the documented order: when both
// the remote proxy and the slowdns layer are on, the proxy CONNECT
// goes through the DNSTT tunnel — not direct TCP. The DNSTT
// resolver here is deliberately invalid (port 99999), so the
// tunnel fails fast at parse time; the error must mention DNSTT,
// which only happens if the proxy dial took the DNSTT branch.
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

func TestReadHTTPResponseHeaders(t *testing.T) {
	// Server side: write a response with headers, then extra bytes
	// (the SSH version string that follows).
	server, client := stdnet.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nX-Test: 1\r\n\r\nSSH-2.0-test"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, status, err := readHTTPResponseHeaders(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	// The bytes after the headers must survive (bufferedConn).
	buf := make([]byte, len("SSH-2.0-test"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "SSH-2.0-test" {
		t.Errorf("bytes after headers = %q, want %q", string(buf), "SSH-2.0-test")
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
