// Package dnstt provides a DNSTT (SlowDNS) dialer: a net.Conn dialer
// whose connections are streams of ONE shared DNSTT session (resolver
// UDP -> KCP -> Noise_NK -> smux, inner "fixed").
//
// The wire code (DNS encoding, Noise, KCP/smux framing) is vendored
// unchanged in this package from the sing-box fork's slowdns client
// (see NOTICE.md). This file is the only new code in the package: it
// owns the shared session (establish + re-establish on death) and
// exposes it as a Dialer, so an outbound (e.g. proxy/ssh) can dial its
// server through the tunnel without a separate process or SOCKS hop.
//
// Inner "fixed" means the server forwards every stream to ONE fixed
// TCP port, so DialContext ignores the requested address: the caller
// must dial the server whose fixed port is the service it wants (for
// proxy/ssh, the SSH server). The first Dial waits for the Noise
// handshake (~6-7 s); a background keeper keeps the session warm.
package dnstt

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// DefaultResolver is used when no resolver is configured.
const DefaultResolver = "1.1.1.1:53"

// DefaultKCPWindow mirrors the dnstt-client default.
const DefaultKCPWindow = 512

// Dialer dials net.Conns over a shared DNSTT session.
type Dialer struct {
	ns         string
	pubkeyHex  string
	resolver   string
	kcpWindow  int
	recordType string

	mu     sync.Mutex
	sess   *Session
	pc     net.PacketConn
	closed bool
	// estab is non-nil while a session establishment is in flight.
	// Establishment runs WITHOUT holding mu (NewSession blocks for
	// the Noise handshake), so Close never blocks on it; concurrent
	// getSession callers wait on estab.done instead of starting a
	// second establishment.
	estab *estabState
}

type estabState struct {
	done chan struct{}
	sess *Session
	err  error
}

// NewDialer validates the settings and returns a Dialer. No network
// I/O happens here; the session is established lazily on first Dial
// (or eagerly via EnsureSession).
func NewDialer(ns, pubkeyHex, resolver string, kcpWindow int) (*Dialer, error) {
	return NewDialerWithRecordType(ns, pubkeyHex, resolver, kcpWindow, "txt")
}

// NewDialerWithRecordType is NewDialer with an explicit DNS record
// type ("txt" or "null"; anything else is rejected at session time).
func NewDialerWithRecordType(ns, pubkeyHex, resolver string, kcpWindow int, recordType string) (*Dialer, error) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return nil, errors.New("dnstt: empty NS domain")
	}
	pubkeyHex = strings.TrimSpace(pubkeyHex)
	pubkey, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pubkey) != KeyLen {
		return nil, errors.New("dnstt: public key must be 64 hex chars (32 bytes)")
	}
	if strings.TrimSpace(resolver) == "" {
		resolver = DefaultResolver
	}
	if kcpWindow <= 0 {
		kcpWindow = DefaultKCPWindow
	}
	if strings.TrimSpace(recordType) == "" {
		recordType = "txt"
	}
	return &Dialer{
		ns:         ns,
		pubkeyHex:  pubkeyHex,
		resolver:   strings.TrimSpace(resolver),
		kcpWindow:  kcpWindow,
		recordType: strings.TrimSpace(recordType),
	}, nil
}

// EnsureSession establishes the shared session if it is not already
// up, in the background-keeper style of dnstt-client: it retries until
// the session is established or ctx is done.
func (d *Dialer) EnsureSession(ctx context.Context) error {
	for {
		if _, err := d.getSession(); err == nil {
			return nil
		} else if ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// DialContext opens a DNSTT stream. The address is ignored (inner
// "fixed": the server forwards every stream to its fixed port); the
// caller must have configured the dialer for the server it wants.
//
// Session establishment (NewSession) blocks for the Noise handshake
// (~6-7 s up, ~60 s timeout on a dead server) and is not itself
// ctx-aware, so it runs in a goroutine: if ctx ends first, DialContext
// returns ctx.Err() and the establishment keeps running in the
// background (a later Dial reuses the session it establishes).
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "" && network != "tcp" {
		return nil, errors.New("dnstt: only tcp is supported, got ", network)
	}
	type sessResult struct {
		sess *Session
		err  error
	}
	sessCh := make(chan sessResult, 1)
	go func() {
		sess, err := d.getSession()
		sessCh <- sessResult{sess, err}
	}()
	var sess *Session
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-sessCh:
		if r.err != nil {
			return nil, r.err
		}
		sess = r.sess
	}
	// OpenStream blocks until the session handshake completes; bound
	// it by the caller's context.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := sess.OpenStream()
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			d.resetSession()
			return nil, errors.New("dnstt: open stream").Base(r.err)
		}
		return r.conn, nil
	}
}

// Close drops the shared session and its UDP socket. It never blocks
// on an in-flight session establishment; a session established after
// Close is discarded at once.
func (d *Dialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return d.closeLocked()
}

func (d *Dialer) closeLocked() error {
	var err error
	if d.sess != nil {
		err = d.sess.Close()
		d.sess = nil
	}
	if d.pc != nil {
		_ = d.pc.Close()
		d.pc = nil
	}
	return err
}

// resetSession drops a (probably dead) session so the next Dial
// establishes a fresh one. Caller must not hold d.mu.
func (d *Dialer) resetSession() {
	d.mu.Lock()
	defer d.mu.Unlock()
	_ = d.closeLocked()
}

// getSession returns the live shared session, establishing it first
// if needed. Concurrent callers share one in-flight establishment.
// Caller must not hold d.mu.
func (d *Dialer) getSession() (*Session, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, errors.New("dnstt: dialer closed")
	}
	if d.sess != nil && !d.sess.IsDead() {
		sess := d.sess
		d.mu.Unlock()
		return sess, nil
	}
	_ = d.closeLocked()
	if d.estab != nil {
		e := d.estab
		d.mu.Unlock()
		<-e.done
		return e.sess, e.err
	}
	e := &estabState{done: make(chan struct{})}
	d.estab = e
	d.mu.Unlock()

	sess, pc, err := d.establish()
	d.mu.Lock()
	d.estab = nil
	e.sess, e.err = sess, err
	if err == nil {
		if d.closed {
			// Dialer was closed while establishing: discard.
			_ = sess.Close()
			_ = pc.Close()
			e.sess, e.err = nil, errors.New("dnstt: dialer closed")
		} else {
			d.sess, d.pc = sess, pc
		}
	}
	close(e.done)
	d.mu.Unlock()
	return e.sess, e.err
}

// establish dials a fresh DNSTT session. It must NOT be called with
// d.mu held: NewSession blocks for the Noise handshake.
func (d *Dialer) establish() (*Session, net.PacketConn, error) {
	host, portStr, err := net.SplitHostPort(d.resolver)
	if err != nil {
		host, portStr = d.resolver, "53"
	}
	if port, err := strconv.Atoi(portStr); err != nil || port <= 0 || port > 65535 {
		return nil, nil, errors.New("dnstt: invalid resolver ", d.resolver)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, portStr))
	if err != nil {
		return nil, nil, errors.New("dnstt: resolve resolver ", d.resolver).Base(err)
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, nil, errors.New("dnstt: listen udp").Base(err)
	}
	pubkey, err := hex.DecodeString(d.pubkeyHex)
	if err != nil || len(pubkey) != KeyLen {
		_ = pc.Close()
		return nil, nil, errors.New("dnstt: public key must be 64 hex chars (32 bytes)")
	}
	sess, err := NewSession(pc, udpAddr, SessionConfig{
		Domain:     d.ns,
		Pubkey:     pubkey,
		KCPWindow:  d.kcpWindow,
		RecordType: d.recordType,
	})
	if err != nil {
		_ = pc.Close()
		return nil, nil, err
	}
	return sess, pc, nil
}
