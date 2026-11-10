package ssh

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/transport/internet"
)

// The payload chain — the HC way of working, as TaptapBox
// implements it. A remote proxy is a plain TCP target, NOT a
// CONNECT tunnel: the payload is sent to the proxy directly, one
// HTTP request at a time, one HTTP response per request, and the
// server's first bytes after the payload decide the framing (a raw
// SSH banner, or WS frames). This is what HC does — Cloudflare
// answers the user's HEAD with 301 and the BMOVE upgrade with 101,
// then speaks raw SSH — and what the old CONNECT dial could never
// do (Cloudflare rejects CONNECT with 400).

// Chain dial deadlines.
const (
	// chainKnockDeadline bounds the Simple-Injector CONNECT knock
	// socket (a fire-and-forget send; no response is read).
	chainKnockDeadline = 2 * time.Second
	// chainPayloadDeadline bounds the payload request/response
	// exchange (not the SSH session).
	chainPayloadDeadline = 5 * time.Second
	// chainPeekPeriod bounds the wait for the server's first bytes
	// after the payload (framing detection).
	chainPeekPeriod = 2 * time.Second
)

// splitRequests splits an expanded payload into request blocks,
// each ending "\r\n\r\n". Empty blocks are dropped. A
// single-request payload yields a single block.
func splitRequests(payload string) []string {
	parts := strings.Split(payload, "\r\n\r\n")
	out := []string{}
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		out = append(out, p+"\r\n\r\n")
	}
	if len(out) == 0 {
		return []string{payload}
	}
	return out
}

// httpStatusCode extracts the code from a status line:
// "HTTP/1.1 101 ..." -> "101" ("" if unparseable).
func httpStatusCode(status string) string {
	f := strings.Fields(status)
	if len(f) >= 2 {
		return f[1]
	}
	return ""
}

// readChainResponse reads one HTTP response (status line + headers
// up to the blank line) and returns the status line. It peeks at
// the first bytes first: a real SSH server answers a payload with
// its version banner, not HTTP headers — those bytes must NOT be
// consumed, so when the reply is not HTTP ("HTTP/...") it returns
// "" with no error and leaves the bytes buffered for framing
// detection and the SSH handshake. The caller stops sending
// further requests on "".
func readChainResponse(br *bufio.Reader) (string, error) {
	peek, err := br.Peek(5)
	if err != nil && len(peek) == 0 {
		return "", err
	}
	if len(peek) < 5 || !strings.HasPrefix(string(peek), "HTTP/") {
		// Not an HTTP response (e.g. an SSH banner): leave the
		// bytes buffered.
		return "", nil
	}
	var status string
	for i := 0; i < 64; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		trim := strings.TrimRight(line, "\r\n")
		if i == 0 {
			status = trim
		}
		if trim == "" {
			return status, nil
		}
	}
	return "", errors.New("ssh: proxy response headers too long")
}

// detectFraming guesses framing from the server's first 4 bytes:
// "raw" for a plain SSH banner, "ws" for an unmasked WS frame
// (FIN + text/binary), "" when it cannot be told yet.
func detectFraming(first []byte) string {
	if len(first) < 4 {
		return ""
	}
	if strings.HasPrefix(string(first), "SSH-") {
		return "raw"
	}
	if (first[0] == 0x81 || first[0] == 0x82) && first[1]&0x80 == 0 && first[1] > 0 {
		return "ws"
	}
	return ""
}

// isWSUpgrade reports whether the (expanded) payload asks for a WS
// upgrade.
func isWSUpgrade(payload string) bool {
	return strings.Contains(strings.ToLower(payload), "upgrade: websocket")
}

// addWSHandshakeHeaders adds Sec-WebSocket-Key + Version 13 to a
// WS upgrade payload that does not have them yet. A strict WS
// server answers 400 / never answers 101 without them, and the
// HTTP Custom example payload does not write them (injector apps
// add them behind the scenes).
func addWSHandshakeHeaders(payload string) string {
	if !isWSUpgrade(payload) {
		return payload
	}
	if strings.Contains(strings.ToLower(payload), "sec-websocket-key") {
		return payload
	}
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return payload
	}
	body := strings.TrimSuffix(payload, "\r\n\r\n")
	return body + "\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key[:]) + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
}

// readWSFrame reads one WS frame from the connection (server ->
// client). Returns opcode and payload (unmasked when masked).
func readWSFrame(r io.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	op := h[0] & 0x0F
	masked := h[1]&0x80 != 0
	length := int64(h[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	if length < 0 || length > 64<<20 {
		return 0, nil, errors.New("ssh: unreasonable WS frame size: ", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return op, payload, nil
}

// wsConn is a client-side WebSocket connection, manual framing
// (stdlib only). Write: one binary frame per Write, FIN=1,
// opcode=2, masked. Read: frames joined until FIN, ping answered
// with pong, close answered and reported as EOF.
type wsConn struct {
	stdnet.Conn
	rbuf []byte // unread remainder of the current frame payload
	roff int
}

func (w *wsConn) Read(b []byte) (int, error) {
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
			_ = w.writeWSFrame(0xA, payload)
			continue
		case 0x8: // close
			_ = w.writeWSFrame(0x8, nil)
			return 0, io.EOF
		case 0x2, 0x1, 0x0: // binary/text/continuation: SSH is a
			// stream, so WS frame splits do not matter — each
			// Read returns one frame, and the SSH layer rejoins
			// them.
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

func (w *wsConn) Write(b []byte) (int, error) {
	if err := w.writeWSFrame(0x2, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConn) writeWSFrame(op byte, payload []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | op // FIN + opcode
	maskBit := byte(0x80)
	n := len(payload)
	var hlen int
	switch {
	case n < 126:
		hdr[1] = maskBit | byte(n)
		hlen = 2
	case n < 65536:
		hdr[1] = maskBit | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hlen = 4
	default:
		hdr[1] = maskBit | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		hlen = 10
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	copy(hdr[hlen:hlen+4], mask[:])
	hlen += 4
	if _, err := w.Conn.Write(hdr[:hlen]); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	_, err := w.Conn.Write(masked)
	return err
}

// dialTarget dials host:port — the remote proxy when one is set,
// else the SSH server — through DNSTT when the slowdns layer is on
// (the DNSTT dialer ignores the destination: its streams always go
// to the tunnel's fixed port, so slowdns + remote proxy only works
// when the proxy IS that fixed endpoint), else a direct TCP dial
// through the core dialer, with retry.
func (c *Client) dialTarget(ctx context.Context, dialer internet.Dialer, host string, port int) (stdnet.Conn, error) {
	addr := stdnet.JoinHostPort(host, strconv.Itoa(port))
	if c.effectiveSlowDns() {
		dialCtx, cancel := context.WithTimeout(ctx, sshHandshakeTimeout)
		defer cancel()
		conn, err := c.dnsttDial.DialContext(dialCtx, "tcp", addr)
		if err != nil {
			return nil, errors.New("ssh: dial target through DNSTT").Base(err)
		}
		return conn, nil
	}
	dest := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress(host),
		Port:    net.Port(port),
	}
	var conn stdnet.Conn
	if err := retry.ExponentialBackoff(3, 200).On(func() error {
		var err error
		conn, err = dialer.Dial(ctx, dest)
		return err
	}); err != nil {
		return nil, errors.New("ssh: dial target").Base(err)
	}
	return conn, nil
}

// sendConnectKnock sends the Simple-Injector CONNECT knock for the
// SNI-only case (TLS on, empty payload, no proxy): a plain CONNECT
// "host:port HTTP/1.0" on a separate plain TCP socket to the SSH
// host, without waiting for a response, then closes the socket.
// The knock primes the SNI path (the DPI/firewall sees a CONNECT
// before the TLS handshake). It is fire-and-forget: a failed knock
// (dial error) is ignored and the main dial proceeds. The knock
// dials the same target as the main dial (the SSH host:port,
// default 22); the CONNECT line names knockPort — the SSH port,
// or 443 when unset — exactly as TaptapBox does it. The knock uses
// a direct TCP dial, never DNSTT: the point is a plain socket to
// the host, and a host that needs DNSTT is not reachable that way
// anyway.
func (c *Client) sendConnectKnock(ctx context.Context, dialer internet.Dialer) {
	knockPort := int(c.config.Port)
	if knockPort <= 0 {
		knockPort = 443
	}
	dest := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress(c.config.Address),
		Port:    net.Port(c.config.Port),
	}
	if dest.Port == 0 {
		dest.Port = 22
	}
	knock, err := dialer.Dial(ctx, dest)
	if err != nil {
		return
	}
	_ = knock.SetDeadline(time.Now().Add(chainKnockDeadline))
	_, _ = io.WriteString(knock, fmt.Sprintf("CONNECT %s:%d HTTP/1.0\n\n", c.config.Address, knockPort))
	_ = knock.Close()
}

// dialChain dials the SSH server through the payload chain and
// returns a connection ready for the SSH handshake. One attempt
// only; the caller (getSSHClient) re-establishes the client on
// failure, which re-runs the chain.
//
// The chain, in order:
//  1. Target: the remote proxy when set (dialed as a plain TCP
//     target — NO CONNECT is sent; the payload goes to the proxy
//     directly), else the SSH server. The dial goes through DNSTT
//     when the slowdns layer is on, else direct TCP.
//  2. SNI-only knock: when the payload is empty, TLS is on and no
//     proxy is set, a plain CONNECT knock is sent on a separate
//     socket first (Simple-Injector style), then closed.
//  3. TLS (when on): handshake BEFORE the payload. In auto
//     (sni_version default) a failed handshake falls back to a
//     fresh plain TCP dial (the server is a plain SSH server); a
//     forced version fails as usual.
//  4. Payload (when set): split per request, one request at a
//     time, one HTTP response per request; stop sending when a
//     101/2xx arrives and requests remain. A non-HTTP reply (a
//     real SSH server's banner) stops the loop too — the bytes
//     stay buffered.
//  5. Framing detection: peek the server's first bytes — "SSH-"
//     is a raw pipe, a WS frame is WS framing; detection wins over
//     the payload's upgrade request. Buffered bytes are carried
//     (the connection is wrapped so nothing is lost). The SNI-only
//     knock case skips the peek: the server behind that TLS waits
//     for the client version first, so peeking would only burn
//     the 2 s timeout.
//  6. WS mode (upgrade request, or WS detected): wrap in wsConn;
//     requires a 101 unless WS was detected. Raw mode (empty
//     payload, or a non-WS payload, or raw detected): return the
//     pipe as-is — the HTTP status is NOT fatal.
//
// The old CONNECT-proxy dial and the Enhanced layer are gone: the
// chain reads one response per payload request, which is what
// Enhanced did, and a remote proxy is a plain target, not a
// CONNECT tunnel. use_enhanced stays accepted (UI compat) but has
// no separate behaviour — the chain reads responses whenever a
// payload is sent.
func (c *Client) dialChain(ctx context.Context, dialer internet.Dialer) (stdnet.Conn, error) {
	// 1. Target.
	var targetHost string
	var targetPort int
	if strings.TrimSpace(c.config.RemoteProxy) != "" {
		var err error
		_, _, targetHost, targetPort, err = parseRemoteProxy(c.config.RemoteProxy)
		if err != nil {
			return nil, err
		}
	} else {
		targetHost = c.config.Address
		targetPort = int(c.config.Port)
		if targetPort <= 0 {
			targetPort = 22
		}
	}

	emptyPayload := strings.TrimSpace(c.config.Payload) == ""
	simpleNoPayload := emptyPayload && c.config.UseTls && strings.TrimSpace(c.config.RemoteProxy) == ""

	// 2. SNI-only knock.
	if simpleNoPayload {
		c.sendConnectKnock(ctx, dialer)
	}

	// 3. Main dial.
	raw, err := c.dialTarget(ctx, dialer, targetHost, targetPort)
	if err != nil {
		return nil, err
	}
	var conn stdnet.Conn = raw
	if c.config.UseTls {
		tlsCfg, err := buildTLSConfig(c.effectiveSNI(), c.config.SniVersion, c.config.Insecure)
		if err != nil {
			raw.Close()
			return nil, err
		}
		tlsConn := tls.Client(raw, tlsCfg)
		_ = raw.SetDeadline(time.Now().Add(sshHandshakeTimeout))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			// TLS -> plain fallback, ONLY for auto (sni_version
			// default): a plain SSH server answers with an SSH
			// banner, not a TLS ServerHello, so the handshake
			// fails fast. Re-dial plain TCP and carry on (the
			// payload, when set, is now sent over the plain
			// path). A forced version fails as usual — a
			// forced-1.3 test against a plain server must stay
			// failed, not silently turn plain.
			_ = raw.Close()
			if !isTLSVersionAuto(c.config.SniVersion) {
				return nil, errors.New("ssh: TLS handshake with server").Base(err)
			}
			raw2, err2 := c.dialTarget(ctx, dialer, targetHost, targetPort)
			if err2 != nil {
				return nil, err2
			}
			conn = raw2
		} else {
			conn = tlsConn
		}
	}

	// 4. Payload, one request at a time, one response per request.
	// Deadline only for the payload exchange, not the session.
	_ = conn.SetDeadline(time.Now().Add(chainPayloadDeadline))
	var br *bufio.Reader
	var statuses []string
	status := ""
	payload := ""
	if emptyPayload {
		br = bufio.NewReader(conn)
	} else {
		payload = substitutePayload(c.config.Payload, c.config.Address, c.config.Port)
		payload = addWSHandshakeHeaders(payload)
		br = bufio.NewReader(conn)
		requests := splitRequests(payload)
		for i, req := range requests {
			if _, err := io.WriteString(conn, req); err != nil {
				conn.Close()
				return nil, errors.New("ssh: send payload").Base(err)
			}
			status, err = readChainResponse(br)
			if err != nil {
				conn.Close()
				return nil, errors.New("ssh: read payload response").Base(err)
			}
			if status == "" {
				// Non-HTTP reply (a real SSH server's banner):
				// stop sending, the bytes stay buffered.
				break
			}
			statuses = append(statuses, status)
			code := httpStatusCode(status)
			if i < len(requests)-1 && (code == "101" || strings.HasPrefix(code, "2")) {
				break
			}
		}
	}

	// 5. Framing detection from the server's first bytes.
	if simpleNoPayload {
		// Simple Injector style: do not peek at the banner.
		// The server behind this TLS waits for the client
		// version first — peeking always burns the timeout
		// and the core version arrives late. Pipe straight
		// through; no payload means no WS upgrade, so the
		// pipe is raw by definition.
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(chainPeekPeriod))
	first, _ := br.Peek(4)
	detected := detectFraming(first)
	_ = conn.SetDeadline(time.Time{})
	// br may already have read more bytes than the headers
	// (buffered); those bytes belong to the next stream, so they
	// must be carried along, not discarded. For WS: the first
	// frame may already be partly buffered. For a raw pipe: the
	// buffered bytes are the start of the SSH banner.
	up := &bufferedConn{Conn: conn, r: br}

	// 6. WS vs raw. Detection wins over the payload's upgrade
	// request.
	useWS := isWSUpgrade(payload)
	if detected == "ws" {
		useWS = true
	} else if detected == "raw" {
		useWS = false
	}
	if useWS {
		if detected == "" && httpStatusCode(status) != "101" {
			up.Close()
			return nil, errors.New("ssh: websocket upgrade rejected: ", status, " (all responses: ", strings.Join(statuses, " | "), ")")
		}
		return &wsConn{Conn: up}, nil
	}
	// Raw pipe: non-WS payload, or empty payload. The HTTP status
	// is NOT fatal here — the socket is returned as-is, letting
	// the SSH layer try. Empty payload: there is no HTTP status
	// at all to validate.
	if emptyPayload {
		return up, nil
	}
	code := httpStatusCode(status)
	if detected == "" && status != "" && !strings.HasPrefix(code, "2") && !strings.HasPrefix(code, "1") {
		up.Close()
		return nil, errors.New("ssh: proxy rejected payload: ", status, " (all responses: ", strings.Join(statuses, " | "), ")")
	}
	return up, nil
}
