package tls

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

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
