package ssh

import (
	"strconv"
	"strings"
)

// substitutePayload renders a custom-payload template (HTTP Custom
// style) for the SSH server: [host] is the SSH server host, [port]
// the SSH server port. Line endings are normalised to CRLF — an
// HTTP-style payload typed in a multi-line editor carries bare LFs,
// and the HTTP parsers in front of the SSH server expect CRLF.
// A payload that already uses CRLF is unchanged.
func substitutePayload(template, host string, port uint32) string {
	if port == 0 {
		port = 22
	}
	s := strings.ReplaceAll(template, "[host]", host)
	s = strings.ReplaceAll(s, "[port]", strconv.Itoa(int(port)))
	// Normalise line endings to CRLF (idempotent for CRLF input).
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	return s
}
