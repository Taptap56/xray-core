// Session builds one DNSTT tunnel session over a DNS packet connection.
//
// Wire code in this package (DNS encoding, Noise, KCP/smux framing) is
// adapted from the public DNSTT library (www.bamsoftware.com/git/dnstt.git,
// GPL-3.0, same licence family as mihomo). It is NOT copied from any
// injector/mod APK: the mod's SlowDNS was only used as evidence that the
// servers in question speak stock DNSTT (see the static-analysis report),
// never as source.
//
// A session is: resolver packet conn -> KCP (stream mode) -> Noise_NK
// client -> smux client. One session is shared by all streams of one
// outbound (mutex-guarded by the caller, mirroring the SSH adapter).
// DNSTT forwards every stream to ONE fixed TCP port on the server, so
// the caller (adapter/outbound/slowdns.go) must speak an inner protocol
// (SOCKS5 handshake, SSH, or nothing for a fixed forward) on each stream.

package dnstt

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/kcp-go"
	"github.com/metacubex/smux"
)

// SessionConfig configures one DNSTT session. Resolver is a UDP DNS
// address (host:port, default 8.8.8.8:53). DoH/DoT are NOT supported by
// this session builder in v1: a resolver that looks like a URL is
// rejected by the adapter before it gets here.
type SessionConfig struct {
	Domain    string // tunnel domain, e.g. t.example.com
	Pubkey    []byte // 32-byte Noise server public key (from 64 hex chars)
	KCPWindow int    // 0 = 64 (DNSTT client default: QueueSize/2)
	MTU       int    // 0 = computed from the domain (DNSTT client formula)
	// RecordType: "", "otomatis", "txt" = TXT; "null" = NULL.
	// Anything else is rejected by NewSession (v1.1.3).
	RecordType string
}

// Session is one shared DNSTT tunnel session.
type Session struct {
	mu        sync.Mutex
	sess      *smux.Session
	kcpConn   *kcp.UDPSession
	noiseConn io.ReadWriteCloser
	pconn     *DNSPacketConn
	transport net.PacketConn
	closed    bool
}

func dnsNameCapacity(domain Name) int {
	capacity := 255
	capacity -= 1
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64
	capacity = capacity * 5 / 8
	return capacity
}

// NewSession builds and handshakes a DNSTT session. transport is the
// resolver packet conn (UDP DNS) and remote is the resolver address the
// transport writes to. The caller owns transport creation: in sing-box it
// must come from the outbound's dialer (which carries the core's bypass
// routing-mark/interface), NOT from a dialer that routes through the
// tunnel itself, or the tunnel's own DNS queries loop back into it.
func NewSession(transport net.PacketConn, remote net.Addr, cfg SessionConfig) (*Session, error) {
	if len(cfg.Pubkey) != KeyLen {
		return nil, fmt.Errorf("slowdns: public key must be %d bytes, got %d", KeyLen, len(cfg.Pubkey))
	}
	domain, err := ParseName(strings.TrimSpace(cfg.Domain))
	if err != nil {
		return nil, fmt.Errorf("slowdns: invalid tunnel domain %q: %w", cfg.Domain, err)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		// DNSTT client: capacity - clientID(8) - padding prefix(1) -
		// padding(3) - data length prefix(1).
		mtu = dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	}
	if mtu < 80 {
		return nil, fmt.Errorf("slowdns: domain %q leaves only %d bytes for payload", cfg.Domain, mtu)
	}
	window := cfg.KCPWindow
	if window <= 0 {
		window = QueueSize / 2
	}

	// v1.1.3: record type — TXT default, NULL untuk server yang hanya
	// menjawab NULL (terbukti di HTTP Custom untuk akun contoh).
	recordType := uint16(RRTypeTXT)
	switch strings.ToLower(strings.TrimSpace(cfg.RecordType)) {
	case "", "otomatis", "auto", "txt":
		recordType = RRTypeTXT
	case "null":
		recordType = RRTypeNULL
	default:
		return nil, fmt.Errorf("slowdns: unsupported record type %q (want txt or null)", cfg.RecordType)
	}

	pconn := NewDNSPacketConnWithRecordType(transport, remote, domain, recordType)
	kcpConn, err := kcp.NewConn2(remote, nil, 0, 0, pconn)
	if err != nil {
		_ = pconn.Close()
		return nil, fmt.Errorf("slowdns: kcp: %w", err)
	}
	cleanup := func() {
		_ = kcpConn.Close()
		_ = pconn.Close()
	}
	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(0, 0, 0, 1)
	kcpConn.SetWindowSize(window, window)
	if !kcpConn.SetMtu(mtu) {
		cleanup()
		return nil, fmt.Errorf("slowdns: kcp refused mtu %d", mtu)
	}
	// Bound the handshake; clear the deadline once the session is up so
	// long-lived streams are not killed by it.
	_ = kcpConn.SetDeadline(time.Now().Add(60 * time.Second))
	noiseConn, err := NewNoiseClient(kcpConn, cfg.Pubkey)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("slowdns: noise handshake: %w", err)
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = 2 * time.Minute
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(noiseConn, smuxConfig)
	if err != nil {
		_ = noiseConn.Close()
		cleanup()
		return nil, fmt.Errorf("slowdns: smux: %w", err)
	}
	_ = kcpConn.SetDeadline(time.Time{})

	return &Session{
		sess:      sess,
		kcpConn:   kcpConn,
		noiseConn: noiseConn,
		pconn:     pconn,
		transport: transport,
	}, nil
}

// OpenStream opens one multiplexed stream on the shared session. The
// returned conn is a smux stream (a net.Conn); the caller speaks the
// inner protocol on it and must Close it when done.
func (s *Session) OpenStream() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.sess == nil || s.sess.IsClosed() {
		return nil, fmt.Errorf("slowdns: session closed")
	}
	st, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	return st, nil
}

// IsClosed reports whether Close has been called.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// IsDead reports whether the session can no longer open streams.
// v1.1.4: this is the fix for "SlowDNS suka timeout, harus restart
// service baru keluar ping lagi". smux closes itself internally on
// keepalive timeout (idle, network change, server drop), but the old
// adapter only checked its own Close() flag, so it kept returning a
// dead session forever until the whole service restarted. A dead
// session must be dropped and recreated (new ClientID + Noise/KCP).
func (s *Session) IsDead() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.sess == nil {
		return true
	}
	return s.sess.IsClosed()
}

// Close tears the session down in dependency order. Safe to call twice.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var firstErr error
	if s.sess != nil {
		if err := s.sess.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.noiseConn != nil {
		_ = s.noiseConn.Close()
	}
	if s.kcpConn != nil {
		if err := s.kcpConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.pconn != nil {
		_ = s.pconn.Close()
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
	return firstErr
}
