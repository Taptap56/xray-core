package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"math/big"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
)

type Interface interface {
	net.Conn
	HandshakeContext(ctx context.Context) error
	VerifyHostname(host string) error
	HandshakeContextServerName(ctx context.Context) string
	NegotiatedProtocol() string
}

var (
	_ buf.Writer = (*Conn)(nil)
	_ Interface  = (*Conn)(nil)
)

type Conn struct {
	*tls.Conn
	suppressCloseNotify atomic.Bool
}

const tlsCloseTimeout = 250 * time.Millisecond

func (c *Conn) SuppressCloseNotify() {
	c.suppressCloseNotify.Store(true)
}

func (c *Conn) Close() error {
	if c.suppressCloseNotify.Load() {
		return c.Conn.NetConn().Close()
	}
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *Conn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *Conn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

func (c *Conn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Client(c, config)
	return &Conn{Conn: tlsConn}
}

// Server initiates a TLS server handshake on the given connection.
func Server(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Server(c, config)
	return &Conn{Conn: tlsConn}
}

type UConn struct {
	*utls.UConn
	suppressCloseNotify atomic.Bool
}

var _ Interface = (*UConn)(nil)

func (c *UConn) SuppressCloseNotify() {
	c.suppressCloseNotify.Store(true)
}

// VerifyHostname memverifikasi sertifikat peer terhadap host.
// Untuk SNI Onering, verifikasi pakai domain asli (real), bukan string
// "onering:real:bug" utuh — sertifikat server tidak pernah diterbitkan
// untuk nama onering. (WS dialer memanggil ini dengan tlsConfig.ServerName
// yang masih string onering utuh; tanpa ini handshake gagal x509 meski
// ClientHello + verifikasi di dalam handshake sudah pakai domain asli.)
func (c *UConn) VerifyHostname(host string) error {
	if real, _, ok := parseOneringSNI(host); ok {
		host = real
	}
	return c.UConn.VerifyHostname(host)
}

func (c *UConn) Close() error {
	if c.suppressCloseNotify.Load() {
		return c.Conn.NetConn().Close()
	}
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *UConn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

// WebsocketHandshakeContext basically calls UConn.Handshake inside it but it will try
// to build outer ALPN to `http/1.1` or `h2 http/1.1` (if manually specified for camouflage)
func (c *UConn) WebsocketHandshakeContext(ctx context.Context) error {
	config := *utils.AccessField[*utls.Config](c, "config")
	ALPN := slices.Clone(config.NextProtos)
	// set other kinds of ALPN to http/1.1
	if !slices.Equal(ALPN, []string{"h2", "http/1.1"}) {
		ALPN = []string{"http/1.1"}
	}
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Do not modify outer ALPN if ECH is used
	// Outer ALPN will be h2,http/1.1, and real http/1.1 in config will be hidden in ECH
	if config.EncryptedClientHelloConfigList != nil {
		config.NextProtos = []string{"http/1.1"}
		return c.HandshakeContext(ctx)
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = ALPN
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: ALPN})
	}
	// Rebuild the client hello and do the handshake
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return c.HandshakeContext(ctx)
}

func (c *UConn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

func (c *UConn) ConnectionState() tls.ConnectionState {
	s := c.UConn.ConnectionState()
	var state tls.ConnectionState
	state.HandshakeComplete = s.HandshakeComplete
	state.Version = s.Version
	state.NegotiatedProtocol = s.NegotiatedProtocol
	state.DidResume = s.DidResume
	state.ServerName = s.ServerName
	state.CipherSuite = s.CipherSuite
	state.PeerCertificates = s.PeerCertificates
	state.VerifiedChains = s.VerifiedChains
	state.SignedCertificateTimestamps = s.SignedCertificateTimestamps
	state.OCSPResponse = s.OCSPResponse
	state.TLSUnique = s.TLSUnique
	state.ECHAccepted = s.ECHAccepted
	return state
}

// parseOneringSNI mem-parse SNI Onering "onering:<real>:<bug>" (dharak36/
// xray-onering, port dari TaptapBox v1.0.44 / TaptapClash v1.0.60).
// real = domain asli server, bug = domain bug. ok=false bila format
// tidak cocok.
func parseOneringSNI(sni string) (real, bug string, ok bool) {
	if !strings.HasPrefix(sni, "onering:") {
		return "", "", false
	}
	parts := strings.Split(sni, ":")
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// oneringBugExtensionData membangun data extension 0xff00 (hasil bedah
// ClientHello Onering asli): daftar server_name berisi domain bug.
// Format: list_len(2) + type(1)=0 + host_len(2) + host. Byte-identik
// dengan TaptapBox / TaptapClash.
func oneringBugExtensionData(bug string) []byte {
	listLen := 3 + len(bug)
	data := make([]byte, 0, 5+len(bug))
	data = append(data, byte(listLen>>8), byte(listLen), 0, byte(len(bug)>>8), byte(len(bug)))
	data = append(data, bug...)
	return data
}

// UClientOnering membuat UConn dengan HelloCustom: spec fingerprint yang
// dimodifikasi (SNI = domain asli, extension 0xff00 berisi domain bug
// paling depan). config.ServerName harus sudah domain asli.
func UClientOnering(c net.Conn, config *utls.Config, fingerprint utls.ClientHelloID, bug string) (*utls.UConn, error) {
	uConn := utls.UClient(c, config, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return nil, err
	}
	for _, ext := range spec.Extensions {
		if sniExt, ok := ext.(*utls.SNIExtension); ok {
			sniExt.ServerName = config.ServerName
		}
	}
	bugData := oneringBugExtensionData(bug)
	spec.Extensions = append([]utls.TLSExtension{&utls.GenericExtension{Id: 0xff00, Data: bugData}}, spec.Extensions...)
	if err := uConn.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	uConn.SetSNI(config.ServerName)
	return uConn, nil
}

func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn {
	// Onering (dharak36/xray-onering, port TB v1.0.44 / TC v1.0.60):
	// SNI "onering:<real>:<bug>" — bug di extension 0xff00 paling
	// depan, domain asli di SNI standar. ServerName diubah ke domain
	// asli dulu (verifikasi sertifikat pakai domain asli).
	if real, bug, ok := parseOneringSNI(config.ServerName); ok {
		cfg := copyConfig(config)
		cfg.ServerName = real
		fp := utls.HelloChrome_Auto
		if fingerprint != nil {
			fp = *fingerprint
		}
		if uConn, err := UClientOnering(c, cfg, fp, bug); err == nil {
			return &UConn{UConn: uConn}
		}
		// Gagal bangun Onering -> jatuh ke jalur normal dengan SNI
		// domain asli (cfg sudah ServerName=real).
		return &UConn{UConn: utls.UClient(c, cfg, fp)}
	}
	utlsConn := utls.UClient(c, copyConfig(config), *fingerprint)
	return &UConn{UConn: utlsConn}
}

func GeneraticUClient(c net.Conn, config *tls.Config) *utls.UConn {
	return utls.UClient(c, copyConfig(config), utls.HelloChrome_Auto)
}

func copyConfig(c *tls.Config) *utls.Config {
	config := &utls.Config{
		Rand:                           c.Rand,
		RootCAs:                        c.RootCAs,
		ServerName:                     c.ServerName,
		InsecureSkipVerify:             c.InsecureSkipVerify,
		VerifyPeerCertificate:          c.VerifyPeerCertificate,
		KeyLogWriter:                   c.KeyLogWriter,
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
		NextProtos:                     c.NextProtos,
	}
	if c.GetClientCertificate != nil {
		config.GetClientCertificate = func(info *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			schemes := make([]tls.SignatureScheme, len(info.SignatureSchemes))
			for i, s := range info.SignatureSchemes {
				schemes[i] = tls.SignatureScheme(s)
			}
			cert, err := c.GetClientCertificate(&tls.CertificateRequestInfo{
				AcceptableCAs:    info.AcceptableCAs,
				SignatureSchemes: schemes,
				Version:          info.Version,
			})
			if err != nil || cert == nil {
				return &utls.Certificate{}, err
			}
			return &utls.Certificate{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey, Leaf: cert.Leaf}, nil
		}
	}
	return config
}

func init() {
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ModernFingerprints))))
	stopAt := int(bigInt.Int64())
	i := 0
	for _, v := range ModernFingerprints {
		if i == stopAt {
			PresetFingerprints["random"] = v
			break
		}
		i++
	}
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomized := utls.HelloRandomizedALPN
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &weights
	randomizednoalpn := utls.HelloRandomizedNoALPN
	randomizednoalpn.Seed, _ = utls.NewPRNGSeed()
	randomizednoalpn.Weights = &weights
	PresetFingerprints["randomized"] = &randomized
	PresetFingerprints["randomizednoalpn"] = &randomizednoalpn
}

func GetFingerprint(name string) (fingerprint *utls.ClientHelloID) {
	if name == "" {
		return &utls.HelloChrome_Auto
	}
	if fingerprint = PresetFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = ModernFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = OtherFingerprints[name]; fingerprint != nil {
		return
	}
	return
}

var PresetFingerprints = map[string]*utls.ClientHelloID{
	// Recommended preset options in GUI clients
	"chrome":           &utls.HelloChrome_Auto,
	"firefox":          &utls.HelloFirefox_Auto,
	"safari":           &utls.HelloSafari_Auto,
	"ios":              &utls.HelloIOS_Auto,
	"android":          &utls.HelloAndroid_11_OkHttp,
	"edge":             &utls.HelloEdge_Auto,
	"360":              &utls.Hello360_Auto,
	"qq":               &utls.HelloQQ_Auto,
	"random":           nil,
	"randomized":       nil,
	"randomizednoalpn": nil,
	"unsafe":           nil,
}

var ModernFingerprints = map[string]*utls.ClientHelloID{
	// One of these will be chosen as `random` at startup
	"hellofirefox_120": &utls.HelloFirefox_120,
	"hellofirefox_148": &utls.HelloFirefox_148,
	"hellochrome_120":  &utls.HelloChrome_120,
	"hellochrome_131":  &utls.HelloChrome_131,
	"hellochrome_133":  &utls.HelloChrome_133,
	"helloios_13":      &utls.HelloIOS_13,
	"helloios_14":      &utls.HelloIOS_14,
	"helloedge_106":    &utls.HelloEdge_106,
	"hellosafari_26_3": &utls.HelloSafari_26_3,
	"hello360_11_0":    &utls.Hello360_11_0,
	"helloqq_11_1":     &utls.HelloQQ_11_1,
}

var OtherFingerprints = map[string]*utls.ClientHelloID{
	// Golang, randomized, auto, and fingerprints that are too old
	"hellogolang":             &utls.HelloGolang,
	"hellorandomized":         &utls.HelloRandomized,
	"hellorandomizedalpn":     &utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":   &utls.HelloRandomizedNoALPN,
	"hellofirefox_auto":       &utls.HelloFirefox_Auto,
	"hellofirefox_55":         &utls.HelloFirefox_55,
	"hellofirefox_56":         &utls.HelloFirefox_56,
	"hellofirefox_63":         &utls.HelloFirefox_63,
	"hellofirefox_65":         &utls.HelloFirefox_65,
	"hellofirefox_99":         &utls.HelloFirefox_99,
	"hellofirefox_102":        &utls.HelloFirefox_102,
	"hellofirefox_105":        &utls.HelloFirefox_105,
	"hellochrome_auto":        &utls.HelloChrome_Auto,
	"hellochrome_58":          &utls.HelloChrome_58,
	"hellochrome_62":          &utls.HelloChrome_62,
	"hellochrome_70":          &utls.HelloChrome_70,
	"hellochrome_72":          &utls.HelloChrome_72,
	"hellochrome_83":          &utls.HelloChrome_83,
	"hellochrome_87":          &utls.HelloChrome_87,
	"hellochrome_96":          &utls.HelloChrome_96,
	"hellochrome_100":         &utls.HelloChrome_100,
	"hellochrome_102":         &utls.HelloChrome_102,
	"hellochrome_106_shuffle": &utls.HelloChrome_106_Shuffle,
	"helloios_auto":           &utls.HelloIOS_Auto,
	"helloios_11_1":           &utls.HelloIOS_11_1,
	"helloios_12_1":           &utls.HelloIOS_12_1,
	"helloandroid_11_okhttp":  &utls.HelloAndroid_11_OkHttp,
	"helloedge_85":            &utls.HelloEdge_85,
	"helloedge_auto":          &utls.HelloEdge_Auto,
	"hellosafari_16_0":        &utls.HelloSafari_16_0,
	"hellosafari_auto":        &utls.HelloSafari_Auto,
	"hello360_auto":           &utls.Hello360_Auto,
	"hello360_7_5":            &utls.Hello360_7_5,
	"helloqq_auto":            &utls.HelloQQ_Auto,

	// Chrome betas
	"hellochrome_100_psk":              &utls.HelloChrome_100_PSK,
	"hellochrome_112_psk_shuf":         &utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_114_padding_psk_shuf": &utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_115_pq":               &utls.HelloChrome_115_PQ,
	"hellochrome_115_pq_psk":           &utls.HelloChrome_115_PQ_PSK,
	"hellochrome_120_pq":               &utls.HelloChrome_120_PQ,
}
