package ssh

import (
	"crypto/tls"
	"strings"

	"github.com/xtls/xray-core/common/errors"
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

// isTLSVersionAuto reports whether the SNI version is auto
// ("default"/""): no forced TLS version, the stack negotiates.
// The TLS -> plain fallback ONLY applies in this mode. When a
// version is forced explicitly, a failed handshake must stay
// failed, not silently turn plain — otherwise a forced-1.3 test
// against a plain server would falsely pass via the plain path.
func isTLSVersionAuto(version string) bool {
	v := strings.ToLower(strings.TrimSpace(version))
	return v == "" || v == sniVersionDefault
}

// buildTLSConfig builds the TLS client config for the TLS layer:
// SNI (default: the SSH server host), the insecure (skip-verify)
// toggle, and the SNI version as min/max.
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

// effectiveSlowDns reports whether the SSH server is dialed
// through DNSTT: the slowdns layer, or (legacy) no layer flag set
// with DNSTT settings present, so older SlowDNS profiles keep
// working without layer flags. Note proto3 bools cannot tell
// "explicitly off" from "unset", so this implication must only
// fire for genuine legacy configs: the app gates dnstt_ns on its
// own slowdns check and never sends it with all layers off.
func (c *Client) effectiveSlowDns() bool {
	if c.config.UseSlowdns {
		return true
	}
	if c.config.UsePayload || c.config.UseEnhanced || c.config.UseTls || c.config.UseSlowdns {
		return false
	}
	return strings.TrimSpace(c.config.DnsttNs) != ""
}

// effectiveSendPayload reports whether a payload is sent: the
// payload layer, or the enhanced layer (which sends the payload
// and then waits for the server's response headers).
func (c *Client) effectiveSendPayload() bool {
	return c.config.UsePayload || c.config.UseEnhanced
}
