package ssh

import (
	"bufio"
	"context"
	"encoding/base64"
	stdnet "net"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/transport/internet"
)

// bufferedConn is a net.Conn whose reads come from a bufio.Reader
// first: bytes a wrapper already read (e.g. HTTP response headers)
// are not lost to the SSH handshake that follows on the same
// connection.
type bufferedConn struct {
	stdnet.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// parseRemoteProxy parses an HTTP Custom "Proxy jarak jauh" value:
// "[user:pass@]host:port" (IPv6: "[2001:db8::1]:80" or
// "user:pass@[2001:db8::1]:80"). Returns user, password, host, port.
func parseRemoteProxy(s string) (user, pass, host string, port int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", "", 0, errors.New("ssh: empty remote proxy")
	}
	// The userinfo (user:pass@) is separated by the last '@': a
	// password may itself contain '@' only percent-encoded, which
	// the proxy would decode — not our concern here.
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		userinfo := s[:i]
		s = s[i+1:]
		if j := strings.IndexByte(userinfo, ':'); j >= 0 {
			user, pass = userinfo[:j], userinfo[j+1:]
		} else {
			user = userinfo
		}
	}
	h, p, err := stdnet.SplitHostPort(s)
	if err != nil {
		return "", "", "", 0, errors.New("ssh: invalid remote proxy ", s).Base(err)
	}
	if h == "" {
		return "", "", "", 0, errors.New("ssh: remote proxy needs a host")
	}
	portNum, err := strconv.Atoi(p)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return "", "", "", 0, errors.New("ssh: invalid remote proxy port ", p)
	}
	return user, pass, h, portNum, nil
}

// readHTTPResponseHeaders reads an HTTP response's headers from conn
// (up to the blank line), discarding them, and returns the
// connection — wrapped so bytes already buffered past the headers
// are not lost — and the response status code. The wait is bounded
// by the caller's context deadline, else the SSH handshake timeout.
// The status code is the caller's to interpret (CONNECT requires
// 2xx; the Enhanced layer only waits for the response).
func readHTTPResponseHeaders(ctx context.Context, conn stdnet.Conn) (stdnet.Conn, int, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(sshHandshakeTimeout))
	}
	defer conn.SetReadDeadline(time.Time{})
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, 0, err
	}
	status := 0
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) >= 2 {
		status, _ = strconv.Atoi(parts[1])
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, 0, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	return &bufferedConn{Conn: conn, r: r}, status, nil
}

// dialProxy dials the remote HTTP CONNECT proxy (first hop) and
// establishes a tunnel to the SSH server. The TCP connection to the
// proxy goes through the DNSTT tunnel when the slowdns layer is on,
// else direct TCP. Note the DNSTT dialer ignores the destination
// address (its streams always go to the tunnel's fixed port), so
// slowdns + remote proxy only works when the proxy IS that fixed
// endpoint; otherwise the CONNECT is sent to the fixed port and
// fails there.
func (c *Client) dialProxy(ctx context.Context, dialer internet.Dialer) (stdnet.Conn, error) {
	proxyUser, proxyPass, proxyHost, proxyPort, err := parseRemoteProxy(c.config.RemoteProxy)
	if err != nil {
		return nil, err
	}
	proxyAddr := stdnet.JoinHostPort(proxyHost, strconv.Itoa(proxyPort))
	var raw stdnet.Conn
	if c.effectiveSlowDns() {
		dialCtx, cancel := context.WithTimeout(ctx, sshHandshakeTimeout)
		defer cancel()
		raw, err = c.dnsttDial.DialContext(dialCtx, "tcp", proxyAddr)
		if err != nil {
			return nil, errors.New("ssh: dial remote proxy through DNSTT").Base(err)
		}
	} else {
		dest := net.Destination{
			Network: net.Network_TCP,
			Address: net.ParseAddress(proxyHost),
			Port:    net.Port(proxyPort),
		}
		if err := retry.ExponentialBackoff(3, 200).On(func() error {
			var err error
			raw, err = dialer.Dial(ctx, dest)
			return err
		}); err != nil {
			return nil, errors.New("ssh: dial remote proxy").Base(err)
		}
	}
	var req strings.Builder
	req.WriteString("CONNECT " + c.serverAddr() + " HTTP/1.1\r\n")
	req.WriteString("Host: " + c.serverAddr() + "\r\n")
	if proxyUser != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPass))
		req.WriteString("Proxy-Authorization: Basic " + cred + "\r\n")
	}
	req.WriteString("\r\n")
	if _, err := raw.Write([]byte(req.String())); err != nil {
		raw.Close()
		return nil, errors.New("ssh: send CONNECT to remote proxy").Base(err)
	}
	conn, status, err := readHTTPResponseHeaders(ctx, raw)
	if err != nil {
		raw.Close()
		return nil, errors.New("ssh: read CONNECT response").Base(err)
	}
	if status < 200 || status >= 300 {
		conn.Close()
		return nil, errors.New("ssh: remote proxy CONNECT failed: ", status)
	}
	return conn, nil
}
