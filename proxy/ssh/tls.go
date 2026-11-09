package ssh

import (
	"crypto/tls"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// SSH method names (Config.Method). Empty means "direct".
const (
	methodDirect  = "direct"
	methodPayload = "payload"
	methodWS      = "ws"
	methodWSTLS   = "ws-tls"
	methodTLS     = "tls"
	methodSlowDNS = "slowdns"
)

// SNI version names (Config.SniVersion). "default" (and empty) means
// auto: no forced TLS version, the stack negotiates.
const (
	sniVersionDefault = "default"
	sniVersionTLS10   = "tls1"
	sniVersionTLS11   = "tls1.1"
	sniVersionTLS12   = "tls1.2"
	sniVersionTLS13   = "tls1.3"
)

// tlsVersionRange maps an SNI version name to a (min, max) TLS
// version pair for crypto/tls. "default"/"" returns (0, 0): no
// Min/MaxVersion set, so Go negotiates freely. An unknown name is
// an error — silently falling back to a different version would
// mislead the user about what was negotiated.
func tlsVersionRange(version string) (min, max uint16, err error) {
	switch strings.ToLower(strings.TrimSpace(version)) {
	case "", sniVersionDefault:
		return 0, 0, nil
	case sniVersionTLS10:
		return tls.VersionTLS10, tls.VersionTLS10, nil
	case sniVersionTLS11:
		return tls.VersionTLS11, tls.VersionTLS11, nil
	case sniVersionTLS12:
		return tls.VersionTLS12, tls.VersionTLS12, nil
	case sniVersionTLS13:
		return tls.VersionTLS13, tls.VersionTLS13, nil
	default:
		return 0, 0, errors.New("ssh: unknown SNI version ", version)
	}
}

// buildTLSConfig builds the TLS client config for the "tls" and
// "ws-tls" methods: SNI (default: the SSH server host), the
// insecure (skip-verify) toggle, and the SNI version as min/max.
func buildTLSConfig(sni, sniVersion string, insecure bool) (*tls.Config, error) {
	min, max, err := tlsVersionRange(sniVersion)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		MinVersion:         min,
		MaxVersion:         max,
	}, nil
}

// effectiveSNI returns the SNI to use: the configured one, or the
// SSH server host when empty.
func (c *Client) effectiveSNI() string {
	if strings.TrimSpace(c.config.Sni) != "" {
		return strings.TrimSpace(c.config.Sni)
	}
	return c.config.Address
}

// effectiveMethod resolves the transport method: an explicit method
// wins; empty + DNSTT settings implies slowdns (older SlowDNS
// profiles have no method field); otherwise direct.
func (c *Client) effectiveMethod() string {
	m := strings.ToLower(strings.TrimSpace(c.config.Method))
	if m != "" {
		return m
	}
	if c.dnsttDial != nil {
		return methodSlowDNS
	}
	return methodDirect
}
