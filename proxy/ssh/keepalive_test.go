package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	stdnet "net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/xtls/xray-core/common"
)

// --- Keep-alive tests ---
//
// The keeper (ssh.go: keepAliveLoop) sends a keepalive@openssh.com
// global request every sshKeepAliveInterval (10 s in production;
// shortened here via the package var) and resets the cached client
// when the probe fails, so a session that died silently while idle
// is detected proactively instead of only on the next failed
// DialContext in Process. Before the keeper existed, all three
// tests below failed: no request ever arrived at the server, a
// dead session stayed cached forever, and there was no keeper
// goroutine to stop at all.

// keepAliveTestServer is a minimal in-process SSH server (password
// auth) that counts keepalive@openssh.com requests (replying true,
// as a real sshd does), forwards direct-tcpip channels to the echo
// server, and lets the test kill its server-side connections to
// simulate a session dying silently while idle.
type keepAliveTestServer struct {
	config    *ssh.ServerConfig
	echoAddr  string
	ln        stdnet.Listener
	mu        sync.Mutex
	keepAlive int
	conns     []*ssh.ServerConn
}

func newKeepAliveTestServer(t *testing.T, echoAddr string) *keepAliveTestServer {
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
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &keepAliveTestServer{config: config, echoAddr: echoAddr, ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(raw)
		}
	}()
	return s
}

func (s *keepAliveTestServer) handle(raw stdnet.Conn) {
	defer raw.Close()
	conn, chans, reqs, err := ssh.NewServerConn(raw, s.config)
	if err != nil {
		return
	}
	defer conn.Close()
	s.mu.Lock()
	s.conns = append(s.conns, conn)
	s.mu.Unlock()
	go func() {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				s.mu.Lock()
				s.keepAlive++
				s.mu.Unlock()
				_ = req.Reply(true, nil)
			} else if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()
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

func (s *keepAliveTestServer) keepAliveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keepAlive
}

// killConnections closes every server-side SSH connection, so the
// client's session dies silently (no FIN/notice at the SSH layer
// the client would otherwise act on — the keeper must notice via
// its next failed probe).
func (s *keepAliveTestServer) killConnections() {
	s.mu.Lock()
	conns := append([]*ssh.ServerConn(nil), s.conns...)
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// setKeepAliveInterval shortens the probe interval for a test and
// restores the 10 s production value afterwards.
func setKeepAliveInterval(t *testing.T, d time.Duration) {
	t.Helper()
	old := sshKeepAliveInterval
	sshKeepAliveInterval = d
	t.Cleanup(func() { sshKeepAliveInterval = old })
}

// establishKeepAliveClient dials the test SSH server through the
// client's own getSSHClient (the path Process uses), so the keeper
// starts exactly as in production.
func establishKeepAliveClient(t *testing.T, c *Client) *ssh.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := c.getSSHClient(ctx, testDialer{})
	if err != nil {
		t.Fatalf("getSSHClient: %v", err)
	}
	return client
}

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestKeepAliveProbesIdleSession proves the keeper actually probes
// an idle session: the server must receive keepalive requests
// while the client sits idle, and the session must still be usable
// for a channel afterwards.
func TestKeepAliveProbesIdleSession(t *testing.T) {
	setKeepAliveInterval(t, 50*time.Millisecond)
	echoAddr := startEchoServer(t)
	srv := newKeepAliveTestServer(t, echoAddr)
	addr := srv.ln.Addr().(*stdnet.TCPAddr)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	defer c.Close()
	client := establishKeepAliveClient(t, c)

	waitFor(t, "at least 2 keepalive requests", 5*time.Second, func() bool {
		return srv.keepAliveCount() >= 2
	})

	// The probed session is still alive and usable.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	channel, err := client.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("channel after keepalives: %v", err)
	}
	defer channel.Close()
	if _, err := channel.Write([]byte("ping")); err != nil {
		t.Fatalf("write channel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(channel, buf); err != nil {
		t.Fatalf("read channel: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want %q", string(buf), "ping")
	}
}

// TestKeepAliveDetectsDeadSession proves the proactive detection:
// once the server-side connection is killed, the keeper's next
// probe fails and the dead client is reset (not left cached), and
// a fresh dial afterwards works again.
func TestKeepAliveDetectsDeadSession(t *testing.T) {
	setKeepAliveInterval(t, 50*time.Millisecond)
	echoAddr := startEchoServer(t)
	srv := newKeepAliveTestServer(t, echoAddr)
	addr := srv.ln.Addr().(*stdnet.TCPAddr)
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	defer c.Close()
	first := establishKeepAliveClient(t, c)
	done := c.keepAliveDone

	// Wait for at least one probe so the session is proven live
	// before it is killed.
	waitFor(t, "first keepalive request", 5*time.Second, func() bool {
		return srv.keepAliveCount() >= 1
	})

	srv.killConnections()

	// The keeper must reset the dead client on its own.
	waitFor(t, "dead client to be reset", 5*time.Second, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.sshClient == nil
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("keeper goroutine did not stop after detecting the dead session")
	}

	// A fresh dial after the reset works (new client, not the dead one).
	second := establishKeepAliveClient(t, c)
	if second == first {
		t.Error("re-established client is the same object as the dead one")
	}
}

// TestKeepAliveStopsOnClose proves the keeper goroutine exits
// cleanly when the client is closed or reset — no leaked goroutine
// probing a dead connection after every reset.
func TestKeepAliveStopsOnClose(t *testing.T) {
	setKeepAliveInterval(t, 50*time.Millisecond)
	echoAddr := startEchoServer(t)
	srv := newKeepAliveTestServer(t, echoAddr)
	addr := srv.ln.Addr().(*stdnet.TCPAddr)

	// Close path.
	c := sshClientFor(t, "127.0.0.1", addr.Port)
	establishKeepAliveClient(t, c)
	done := c.keepAliveDone
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keeper goroutine did not stop after Close")
	}
	c.mu.Lock()
	cached := c.sshClient
	c.mu.Unlock()
	if cached != nil {
		t.Error("sshClient still cached after Close")
	}

	// resetClient path: the old keeper must stop, and a fresh
	// client must start a new keeper (not reuse the stopped one).
	c2 := sshClientFor(t, "127.0.0.1", addr.Port)
	defer c2.Close()
	establishKeepAliveClient(t, c2)
	oldDone := c2.keepAliveDone
	c2.resetClient()
	select {
	case <-oldDone:
	case <-time.After(2 * time.Second):
		t.Fatal("keeper goroutine did not stop after resetClient")
	}
	establishKeepAliveClient(t, c2)
	if c2.keepAliveDone == oldDone {
		t.Error("re-established client reused the stopped keeper's done channel")
	}
	waitFor(t, "keepalive from the re-established client", 5*time.Second, func() bool {
		return srv.keepAliveCount() >= 1
	})
}
