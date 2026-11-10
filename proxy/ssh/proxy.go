package ssh

import (
	"bufio"
	stdnet "net"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
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
// The chain dials the proxy as a plain TCP target and sends the
// payload to it directly (no CONNECT), so the user/password are
// parsed only to validate the format — no Proxy-Authorization
// header is ever sent.
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
