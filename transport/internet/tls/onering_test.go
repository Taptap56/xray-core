package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/utils"
	utls "github.com/refraction-networking/utls"
)

// TestOneringServerNameAfterUClient memastikan ServerName di config utls
// (yang dipakai verifikasi sertifikat) sudah jadi domain asli, bukan
// string onering utuh. Ini yang bikin log HP gagal x509.
func TestOneringServerNameAfterUClient(t *testing.T) {
	cfg := &tls.Config{
		ServerName:         "onering:leaseweb4.svrkencang.web.id:support.zoom.us",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}
	c1, _ := net.Pipe()
	defer c1.Close()

	conn := UClient(c1, cfg, nil)
	uconn, ok := conn.(*UConn)
	if !ok {
		t.Fatalf("UClient tidak mengembalikan *UConn, tapi %T", conn)
	}

	ucfg := *utils.AccessField[*utls.Config](uconn, "config")
	t.Logf("config.ServerName setelah UClient = %q", ucfg.ServerName)
	if ucfg.ServerName != "leaseweb4.svrkencang.web.id" {
		t.Errorf("config.ServerName = %q, mau %q", ucfg.ServerName, "leaseweb4.svrkencang.web.id")
	}

	for _, ext := range uconn.Extensions {
		if sniExt, ok := ext.(*utls.SNIExtension); ok {
			t.Logf("SNIExtension.ServerName = %q", sniExt.ServerName)
			if sniExt.ServerName != "leaseweb4.svrkencang.web.id" {
				t.Errorf("SNIExtension.ServerName = %q, mau %q", sniExt.ServerName, "leaseweb4.svrkencang.web.id")
			}
		}
	}

	// Simulasi WebsocketHandshakeContext: BuildHandshakeState lalu cek lagi.
	_ = uconn.BuildHandshakeState()
	ucfg2 := *utils.AccessField[*utls.Config](uconn, "config")
	t.Logf("config.ServerName setelah BuildHandshakeState = %q", ucfg2.ServerName)
	if ucfg2.ServerName != "leaseweb4.svrkencang.web.id" {
		t.Errorf("setelah BuildHandshakeState, config.ServerName = %q, mau %q", ucfg2.ServerName, "leaseweb4.svrkencang.web.id")
	}
}

// TestOneringParse mem-parse SNI Onering "onering:<real>:<bug>".
func TestOneringParse(t *testing.T) {
	real, bug, ok := parseOneringSNI("onering:leaseweb4.svrkencang.web.id:chat.sociomile.com")
	if !ok || real != "leaseweb4.svrkencang.web.id" || bug != "chat.sociomile.com" {
		t.Fatalf("parseOneringSNI gagal: real=%q bug=%q ok=%v", real, bug, ok)
	}
	if _, _, ok := parseOneringSNI("support.zoom.us"); ok {
		t.Fatalf("parseOneringSNI terima SNI biasa")
	}
	if _, _, ok := parseOneringSNI("onering::bug"); ok {
		t.Fatalf("parseOneringSNI terima real kosong")
	}
	if _, _, ok := parseOneringSNI("onering:real:"); ok {
		t.Fatalf("parseOneringSNI terima bug kosong")
	}
}

// TestOneringBugExtensionData memastikan byte data 0xff00 persis
// (byte-identik TaptapBox / TaptapClash).
func TestOneringBugExtensionData(t *testing.T) {
	got := oneringBugExtensionData("chat.sociomile.com")
	want := []byte{0x00, 0x15, 0x00, 0x00, 0x12}
	want = append(want, []byte("chat.sociomile.com")...)
	if len(got) != len(want) {
		t.Fatalf("oneringBugExtensionData: got %x, mau %x", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("oneringBugExtensionData: got %x, mau %x", got, want)
		}
	}
}

// TestOneringClientHello dial TLS ke listener lokal dengan SNI
// "onering:<real>:<bug>" lalu memastikan ClientHello yang terkirim:
// extension 0xff00 (bug) PALING DEPAN, dan SNI standar (0x0000) = real.
// Ini replika byte-level dari tangkapan ClientHello Onering asli
// (dharak36/xray-onering), port dari TaptapBox TestOneringClientHello.
func TestOneringClientHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	helloCh := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 8192)
		n, _ := conn.Read(buf)
		helloCh <- append([]byte(nil), buf[:n]...)
	}()

	ctx := context.Background()
	fp := utls.HelloChrome_Auto
	cfg := &tls.Config{
		ServerName:         "onering:leaseweb4.svrkencang.web.id:chat.sociomile.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	uConn := UClient(conn, cfg, &fp)
	// Handshake PASTI gagal (server tidak balas ServerHello) — yang
	// penting ClientHello sudah terkirim dan tertangkap.
	_ = uConn.(*UConn).HandshakeContext(ctx)

	var raw []byte
	select {
	case raw = <-helloCh:
	case <-time.After(5 * time.Second):
		t.Fatal("tidak ada ClientHello tertangkap")
	}
	if len(raw) < 5 || raw[0] != 0x16 {
		t.Fatalf("bukan TLS record: %x", raw[:min(8, len(raw))])
	}
	recLen := int(raw[3])<<8 | int(raw[4])
	hs := raw[5:]
	if len(hs) < recLen || hs[0] != 0x01 {
		t.Fatalf("bukan ClientHello")
	}
	body := hs[4:]
	p := 2 + 32
	sessLen := int(body[p])
	p += 1 + sessLen
	csLen := int(body[p])<<8 | int(body[p+1])
	p += 2 + csLen
	compLen := int(body[p])
	p += 1 + compLen
	extTotal := int(body[p])<<8 | int(body[p+1])
	p += 2
	end := p + extTotal
	if end > len(body) {
		t.Fatalf("extensions melebihi body")
	}
	var extTypes []uint16
	var sni, bug string
	for p+4 <= end {
		etype := uint16(body[p])<<8 | uint16(body[p+1])
		elen := int(body[p+2])<<8 | int(body[p+3])
		p += 4
		ext := body[p : p+elen]
		p += elen
		extTypes = append(extTypes, etype)
		if etype == 0xff00 {
			// data = list_len(2) + type(1) + host_len(2) + host
			if len(ext) < 5 {
				t.Fatalf("ext 0xff00 terlalu pendek: %x", ext)
			}
			hl := int(ext[3])<<8 | int(ext[4])
			bug = string(ext[5 : 5+hl])
		}
		if etype == 0x0000 {
			if len(ext) < 5 {
				t.Fatalf("ext SNI terlalu pendek: %x", ext)
			}
			hl := int(ext[3])<<8 | int(ext[4])
			sni = string(ext[5 : 5+hl])
		}
	}
	if len(extTypes) == 0 || extTypes[0] != 0xff00 {
		t.Fatalf("extension pertama = 0x%04x, mau 0xff00 (bug di depan). urutan: %x", extTypes[0], extTypes)
	}
	if bug != "chat.sociomile.com" {
		t.Fatalf("bug di 0xff00 = %q, mau chat.sociomile.com", bug)
	}
	if sni != "leaseweb4.svrkencang.web.id" {
		t.Fatalf("SNI standar = %q, mau leaseweb4.svrkencang.web.id", sni)
	}
}

// TestOneringRealTLSHandshake: handshake TLS beneran ke server lokal
// dengan sertifikat untuk domain asli. Kalau verifikasi pakai domain asli
// (real) -> handshake sukses. Kalau pakai string onering utuh -> gagal x509
// persis seperti log HP.
func TestOneringRealTLSHandshake(t *testing.T) {
	// Buat sertifikat self-signed untuk leaseweb4.svrkencang.web.id
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaseweb4.svrkencang.web.id"},
		DNSNames:     []string{"leaseweb4.svrkencang.web.id", "*.svrkencang.web.id"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	// Server TLS lokal
	srvCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srvCert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// Baca ClientHello saja, lalu tutup (handshake server selesai di Accept)
				buf := make([]byte, 4096)
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				conn.Read(buf)
			}(c)
		}
	}()

	// Client: SNI onering, RootCAs = cert server (self-signed)
	fp := utls.HelloChrome_Auto
	cfg := &tls.Config{
		ServerName: "onering:leaseweb4.svrkencang.web.id:support.zoom.us",
		RootCAs:    pool,
		NextProtos: []string{"http/1.1"},
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	uConn := UClient(raw, cfg, &fp)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = uConn.(*UConn).HandshakeContext(ctx)
	if err != nil {
		t.Fatalf("HandshakeContext gagal: %v (kalau x509 sebut 'onering:...' berarti verifikasi pakai string utuh)", err)
	}
	t.Logf("HandshakeContext SUKSES — verifikasi sertifikat pakai domain asli")
}

// TestOneringVerifyHostname: sesudah handshake, VerifyHostname dengan
// string onering utuh harus sukses (dipetakan ke domain asli). Ini yang
// dipanggil WS dialer dengan tlsConfig.ServerName — tanpa pemetaan ini,
// handshake gagal x509 meski ClientHello + verifikasi dalam handshake
// sudah benar.
func TestOneringVerifyHostname(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaseweb4.svrkencang.web.id"},
		DNSNames:     []string{"leaseweb4.svrkencang.web.id", "*.svrkencang.web.id"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	srvCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srvCert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4096)
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				conn.Read(buf)
			}(c)
		}
	}()

	fp := utls.HelloChrome_Auto
	cfg := &tls.Config{
		ServerName: "onering:leaseweb4.svrkencang.web.id:support.zoom.us",
		RootCAs:    pool,
		NextProtos: []string{"http/1.1"},
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	uConn := UClient(raw, cfg, &fp).(*UConn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := uConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("HandshakeContext gagal: %v", err)
	}
	// Inilah yang dipanggil WS dialer: VerifyHostname(tlsConfig.ServerName)
	// dengan string onering utuh.
	if err := uConn.VerifyHostname("onering:leaseweb4.svrkencang.web.id:support.zoom.us"); err != nil {
		t.Fatalf("VerifyHostname(onering:...) gagal: %v", err)
	}
	t.Logf("VerifyHostname(onering:...) SUKSES — dipetakan ke domain asli")
	// Sanity: VerifyHostname biasa tetap jalan.
	if err := uConn.VerifyHostname("leaseweb4.svrkencang.web.id"); err != nil {
		t.Fatalf("VerifyHostname(real) gagal: %v", err)
	}
}
