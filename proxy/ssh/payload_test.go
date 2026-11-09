package ssh

import "testing"

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

	// No placeholders: only the line endings change.
	got = substitutePayload("HELLO\n", "example.com", 22)
	if got != "HELLO\r\n" {
		t.Fatalf("no placeholders = %q, want %q", got, "HELLO\r\n")
	}
}
