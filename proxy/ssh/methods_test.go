package ssh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// testDialer dials plain TCP to the destination, so the SSH dial
// methods can be exercised without a full core.
type testDialer struct{}

func (testDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	return stdnet.Dial("tcp", dest.NetAddr())
}

func (testDialer) DestIpAddress() stdnet.IP { return nil }

func (testDialer) SetOutboundGateway(ctx context.Context, ob *session.Outbound) {}

// bufferedConn is a net.Conn whose reads come from a bufio.Reader
// first: the bytes a wrapper already read (e.g. a payload) are not
// lost to the SSH handshake.
type bufferedConn struct {
	stdnet.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

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

// dialSSHAndEcho dials the SSH server through the client's transport
// (the method under test), opens a direct-tcpip channel to the echo
// server, and verifies the echo. It proves the transport + SSH
// handshake + channel all work end to end.
func dialSSHAndEcho(t *testing.T, c *Client, echoAddr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport, err := c.dialTransport(ctx, testDialer{})
	if err != nil {
		t.Fatalf("dialTransport: %v", err)
	}
	defer transport.Close()
	sshCfg, err := c.sshClientConfig()
	if err != nil {
		t.Fatalf("sshClientConfig: %v", err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(transport, c.serverAddr(), sshCfg)
	if err != nil {
		t.Fatalf("SSH handshake: %v", err)
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	channel, err := client.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer channel.Close()
	if _, err := channel.Write([]byte("hello-ssh")); err != nil {
		t.Fatalf("write channel: %v", err)
	}
	buf := make([]byte, len("hello-ssh"))
	if _, err := io.ReadFull(channel, buf); err != nil {
		t.Fatalf("read channel: %v", err)
	}
	if string(buf) != "hello-ssh" {
		t.Fatalf("echo = %q, want %q", string(buf), "hello-ssh")
	}
}

func sshClientFor(t *testing.T, host string, port int, method string) *Client {
	t.Helper()
	return &Client{config: &Config{
		Address:  host,
		Port:     uint32(port),
		Username: "alice",
		Password: "secret",
		Method:   method,
	}}
}

// TestDialDirectEndToEnd is the baseline: plain TCP dial + SSH.
func TestDialDirectEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.serveListener(t, ln, nil)
	addr := ln.Addr().(*stdnet.TCPAddr)
	dialSSHAndEcho(t, sshClientFor(t, "127.0.0.1", addr.Port, ""), echoAddr)
}

// TestDialPayloadEndToEnd proves the payload method: the server
// reads the HTTP-style payload first (and checks its content), then
// the SSH handshake follows on the same connection.
func TestDialPayloadEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*stdnet.TCPAddr)
	wantPayload := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Port: " + strconv.Itoa(addr.Port) + "\r\n\r\n"
	// Read the payload up to the end of the HTTP headers, verify it,
	// and keep the buffered bytes for the SSH handshake.
	wrap := func(raw stdnet.Conn) (stdnet.Conn, error) {
		r := bufio.NewReader(raw)
		var sb strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return nil, err
			}
			sb.WriteString(line)
			if sb.String() == wantPayload {
				break
			}
			if sb.Len() > len(wantPayload)+64 {
				return nil, fmt.Errorf("payload mismatch: got %q", sb.String())
			}
		}
		return &bufferedConn{Conn: raw, r: r}, nil
	}
	srv.serveListener(t, ln, wrap)
	c := sshClientFor(t, "127.0.0.1", addr.Port, "payload")
	c.config.Payload = "GET / HTTP/1.1\nHost: [host]\nX-Port: [port]\n\n"
	dialSSHAndEcho(t, c, echoAddr)
}

// TestDialWSEndToEnd proves the WS method: the SSH server sits
// behind a WebSocket upgrade, and the client dials it over WS.
func TestDialWSEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	var gotPath, gotHost string
	upgrader := websocket.Upgrader{}
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHost = r.Host
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		srv.wg.Add(1)
		srv.serve(newWSConn(ws))
	}))
	defer httpSrv.Close()
	u := strings.TrimPrefix(httpSrv.URL, "http://")
	host, portStr, err := stdnet.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	c := sshClientFor(t, host, port, "ws")
	c.config.WsPath = "/ssh"
	c.config.WsHost = "ws.example.com"
	dialSSHAndEcho(t, c, echoAddr)
	if gotPath != "/ssh" {
		t.Errorf("WS path = %q, want %q", gotPath, "/ssh")
	}
	if gotHost != "ws.example.com" {
		t.Errorf("WS Host = %q, want %q", gotHost, "ws.example.com")
	}
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

// TestDialTLSEndToEnd proves the TLS method: direct TLS (SNI only)
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
	c := sshClientFor(t, "127.0.0.1", addr.Port, "tls")
	c.config.Sni = "127.0.0.1"
	c.config.SniVersion = "tls1.2"
	c.config.Insecure = true
	dialSSHAndEcho(t, c, echoAddr)
}

// TestDialWSTLSEndToEnd proves the WS+TLS method: WebSocket over
// TLS to the SSH server, self-signed cert, insecure skip-verify.
func TestDialWSTLSEndToEnd(t *testing.T) {
	echoAddr := startEchoServer(t)
	srv := newMethodTestSSHServer(t, echoAddr)
	upgrader := websocket.Upgrader{}
	httpSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		srv.wg.Add(1)
		srv.serve(newWSConn(ws))
	}))
	defer httpSrv.Close()
	u := strings.TrimPrefix(httpSrv.URL, "https://")
	host, portStr, err := stdnet.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	c := sshClientFor(t, host, port, "ws-tls")
	c.config.WsPath = "/ssh"
	c.config.SniVersion = "tls1.2"
	c.config.Insecure = true
	dialSSHAndEcho(t, c, echoAddr)
}
