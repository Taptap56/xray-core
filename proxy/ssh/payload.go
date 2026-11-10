package ssh

import (
	"regexp"
	"strconv"
	"strings"
)

// defaultUserAgent is the User-Agent substituted for the [ua]
// placeholder in a custom payload: a common Chrome-on-Android
// string, the same kind HTTP Custom sends for [ua]. Sending the
// literal "[ua]" would be meaningless to the server in front.
const defaultUserAgent = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

// HC-style placeholders, matched case-insensitively.
var (
	crlfPlaceholder = regexp.MustCompile(`(?i)\[crlf\]`)
	lfPlaceholder   = regexp.MustCompile(`(?i)\[lf\]`)
	crPlaceholder   = regexp.MustCompile(`(?i)\[cr\]`)
	uaPlaceholder   = regexp.MustCompile(`(?i)\[ua\]`)
)

// substitutePayload renders a custom-payload template (HTTP Custom
// style) for the SSH server: [host] is the SSH server host, [port]
// the SSH server port, [protocol] the HTTP version ("HTTP/1.1").
// HC line-ending placeholders become real line endings ([crlf] →
// CRLF, [lf] → LF, [cr] → CR) and [ua] becomes a standard
// User-Agent — without this, a payload typed with [crlf] tokens
// goes out as one long line with no line ending at all, and the SSH
// version string sticks to the same line, so the server never sees
// a line starting with "SSH-". Line endings are then normalised to
// CRLF — an HTTP-style payload typed in a multi-line editor carries
// bare LFs, and the HTTP parsers in front of the SSH server expect
// CRLF. A payload that already uses CRLF is unchanged. Finally, a
// payload that does not end with a blank line gets "\r\n\r\n"
// appended (trailing line endings trimmed first), so the server
// always sees a complete HTTP request — the chain splits the
// payload into requests on "\r\n\r\n", and an unterminated last
// request would never get its response.
func substitutePayload(template, host string, port uint32) string {
	if port == 0 {
		port = 22
	}
	s := strings.ReplaceAll(template, "[host]", host)
	s = strings.ReplaceAll(s, "[port]", strconv.Itoa(int(port)))
	s = strings.ReplaceAll(s, "[protocol]", "HTTP/1.1")
	// HC placeholders first, so the LF→CRLF normalisation below
	// also turns a [lf] into a CRLF (and leaves a [crlf] as one).
	s = crlfPlaceholder.ReplaceAllString(s, "\r\n")
	s = lfPlaceholder.ReplaceAllString(s, "\n")
	s = crPlaceholder.ReplaceAllString(s, "\r")
	s = uaPlaceholder.ReplaceAllString(s, defaultUserAgent)
	// Normalise line endings to CRLF (idempotent for CRLF input).
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	if !strings.HasSuffix(s, "\r\n\r\n") {
		s = strings.TrimRight(s, "\r\n") + "\r\n\r\n"
	}
	return s
}
