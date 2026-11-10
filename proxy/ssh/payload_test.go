package ssh

import (
	"strings"
	"testing"
)

func TestSubstitutePayload(t *testing.T) {
	// [host] and [port] are substituted; bare LFs become CRLF.
	got := substitutePayload("GET / HTTP/1.1\nHost: [host]\nX-Port: [port]\n\n", "example.com", 3128)
	want := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Port: 3128\r\n\r\n"
	if got != want {
		t.Fatalf("substitutePayload = %q, want %q", got, want)
	}

	// A payload that already uses CRLF is unchanged.
	got = substitutePayload("GET / HTTP/1.1\r\nHost: [host]\r\n\r\n", "example.com", 22)
	want = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if got != want {
		t.Fatalf("CRLF payload = %q, want %q", got, want)
	}

	// Port 0 means the SSH default 22.
	got = substitutePayload("CONNECT [host]:[port] HTTP/1.1\n\n", "ssh.example.com", 0)
	want = "CONNECT ssh.example.com:22 HTTP/1.1\r\n\r\n"
	if got != want {
		t.Fatalf("port 0 = %q, want %q", got, want)
	}

	// No placeholders: the line endings change, and the blank
	// line is appended (a payload must end with "\r\n\r\n").
	got = substitutePayload("HELLO\n", "example.com", 22)
	if got != "HELLO\r\n\r\n" {
		t.Fatalf("no placeholders = %q, want %q", got, "HELLO\r\n\r\n")
	}

	// HC-style line-ending placeholders: [crlf] becomes a real
	// CRLF, [lf] a bare LF (normalised to CRLF), [cr] a bare CR.
	got = substitutePayload("GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]", "example.com", 22)
	want = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if got != want {
		t.Fatalf("[crlf] = %q, want %q", got, want)
	}
	got = substitutePayload("A[lf]B[cr]C", "example.com", 22)
	want = "A\r\nB\rC\r\n\r\n"
	if got != want {
		t.Fatalf("[lf]/[cr] = %q, want %q", got, want)
	}

	// [ua] is replaced with a real User-Agent, never sent literally.
	// wantUA pins the exact User-Agent the implementation must
	// substitute (a common Chrome-on-Android string).
	const wantUA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
	got = substitutePayload("User-Agent: [ua]\r\n", "example.com", 22)
	if strings.Contains(got, "[ua]") {
		t.Fatalf("[ua] survived: %q", got)
	}
	if got != "User-Agent: "+wantUA+"\r\n\r\n" {
		t.Fatalf("[ua] = %q, want %q", got, "User-Agent: "+wantUA+"\r\n\r\n")
	}

	// [protocol] becomes the HTTP version.
	got = substitutePayload("GET / [protocol]\r\nHost: [host]\r\n\r\n", "example.com", 22)
	want = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if got != want {
		t.Fatalf("[protocol] = %q, want %q", got, want)
	}

	// Auto-append: a payload without a trailing blank line gets
	// "\r\n\r\n" appended (trailing line endings trimmed first,
	// so no triple blank line).
	got = substitutePayload("GET / HTTP/1.1\r\nHost: [host]\r\n", "example.com", 22)
	want = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if got != want {
		t.Fatalf("auto-append = %q, want %q", got, want)
	}
	// Already ending with a blank line (even an extra one): left
	// alone — the append only fires when there is no trailing
	// blank line at all, exactly like TaptapBox.
	got = substitutePayload("GET / HTTP/1.1\r\nHost: [host]\r\n\r\n\r\n", "example.com", 22)
	want = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n\r\n"
	if got != want {
		t.Fatalf("already terminated = %q, want %q", got, want)
	}

	// Placeholders are case-insensitive ([CRLF], [UA]).
	got = substitutePayload("GET / HTTP/1.1[CRLF]User-Agent: [UA][CRLF][CRLF]", "example.com", 22)
	want = "GET / HTTP/1.1\r\nUser-Agent: " + wantUA + "\r\n\r\n"
	if got != want {
		t.Fatalf("uppercase placeholders = %q, want %q", got, want)
	}

	// The user's exact payload shape: [crlf] tokens, [ua], and
	// [host] pointing at the SSH server. The result must end with
	// a blank line (\r\n\r\n) and contain no placeholder token.
	userPayload := "HEAD / HTTP/1.1[crlf]Host: edu.ruangguru.com:80[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]BMOVE / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
	got = substitutePayload(userPayload, "ssh.example.com", 3128)
	want = "HEAD / HTTP/1.1\r\nHost: edu.ruangguru.com:80\r\nConnection: Keep-Alive\r\nUser-Agent: " + wantUA + "\r\n\r\n" +
		"BMOVE / HTTP/1.1\r\nHost: ssh.example.com\r\nUpgrade: websocket\r\n\r\n"
	if got != want {
		t.Fatalf("user payload = %q, want %q", got, want)
	}
	if !strings.HasSuffix(got, "\r\n\r\n") {
		t.Fatalf("user payload does not end with a blank line: %q", got)
	}
	for _, token := range []string{"[crlf]", "[lf]", "[cr]", "[ua]", "[host]", "[port]"} {
		if strings.Contains(got, token) {
			t.Fatalf("user payload still contains %q: %q", token, got)
		}
	}
}
