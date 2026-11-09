package ssh

import (
	"context"
	"io"
	stdnet "net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// wsHandshakeTimeout bounds the WebSocket handshake.
const wsHandshakeTimeout = 15 * time.Second

// wsConn adapts a gorilla WebSocket connection to a net.Conn, so the
// SSH client can run its handshake and channels over it: writes are
// framed as WS binary messages, reads unframe the next message.
// It mirrors transport/internet/websocket.connection (same Read
// loop, same close-frame handling) without the heartbeat and
// WriteMultiBuffer the core transport needs.
type wsConn struct {
	conn   *websocket.Conn
	reader io.Reader
}

func newWSConn(conn *websocket.Conn) *wsConn {
	return &wsConn{conn: conn}
}

func (c *wsConn) Read(b []byte) (int, error) {
	for {
		if c.reader != nil {
			n, err := c.reader.Read(b)
			if err == nil {
				return n, nil
			}
			// End of this message: move on to the next one.
			c.reader = nil
			continue
		}
		_, r, err := c.conn.NextReader()
		if err != nil {
			// A normal close (1000) or no-status close (1005) ends
			// the byte stream the same way a FIN does.
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseNoStatusReceived) {
				return 0, io.EOF
			}
			return 0, err
		}
		c.reader = r
	}
}

func (c *wsConn) Write(b []byte) (int, error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) Close() error {
	_ = c.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(5*time.Second))
	return c.conn.Close()
}

func (c *wsConn) LocalAddr() stdnet.Addr  { return c.conn.LocalAddr() }
func (c *wsConn) RemoteAddr() stdnet.Addr { return c.conn.RemoteAddr() }

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// effectiveWSHost returns the WebSocket Host header value: the
// configured WS host, or the SSH server host when empty.
func (c *Client) effectiveWSHost() string {
	if strings.TrimSpace(c.config.WsHost) != "" {
		return strings.TrimSpace(c.config.WsHost)
	}
	return c.config.Address
}

// effectiveWSPath returns the WebSocket path, defaulting to "/".
// A query string ("/ws?token=…") is preserved.
func (c *Client) effectiveWSPath() (path, rawQuery string) {
	p := strings.TrimSpace(c.config.WsPath)
	if p == "" {
		return "/", ""
	}
	if i := strings.Index(p, "?"); i >= 0 {
		rawQuery = p[i+1:]
		p = p[:i]
	}
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p, rawQuery
}

// dialWebSocket dials the SSH server over WebSocket (plain "ws", or
// "wss" when useTLS). The underlying TCP connection always goes to
// the SSH server address via the core dialer; the WS Host header
// carries the configured WS host (hostname only, core convention —
// the port is not part of it). For wss the TLS config uses the
// effective SNI, the insecure toggle and the SNI version.
func (c *Client) dialWebSocket(ctx context.Context, dialer internet.Dialer, useTLS bool) (stdnet.Conn, error) {
	port := c.config.Port
	if port == 0 {
		port = 22
	}
	host := c.effectiveWSHost()
	path, rawQuery := c.effectiveWSPath()

	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}
	u := &url.URL{
		Scheme:   scheme,
		Host:     stdnet.JoinHostPort(host, net.Port(port).String()),
		Path:     path,
		RawQuery: rawQuery,
	}

	wsDialer := &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (stdnet.Conn, error) {
			// The URL host is the WS host; the TCP connection goes
			// to the SSH server itself.
			dest := net.Destination{
				Network: net.Network_TCP,
				Address: net.ParseAddress(c.config.Address),
				Port:    net.Port(port),
			}
			conn, err := dialer.Dial(ctx, dest)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		HandshakeTimeout: wsHandshakeTimeout,
	}
	if useTLS {
		tlsCfg, err := buildTLSConfig(c.effectiveSNI(), c.config.SniVersion, c.config.Insecure)
		if err != nil {
			return nil, err
		}
		wsDialer.TLSClientConfig = tlsCfg
	}

	// Host header: hostname only (core WS convention), not host:port.
	header := http.Header{}
	header.Set("Host", host)

	dialCtx, cancel := context.WithTimeout(ctx, wsHandshakeTimeout)
	defer cancel()
	ws, _, err := wsDialer.DialContext(dialCtx, u.String(), header)
	if err != nil {
		return nil, errors.New("ssh: dial WebSocket").Base(err)
	}
	return newWSConn(ws), nil
}
