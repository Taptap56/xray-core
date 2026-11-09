# DNSTT transport — provenance

The wire code in this directory (DNS name encoding, TXT downstream,
Noise_NK handshake, KCP/smux framing, packet queues) is adapted from the
public DNSTT library:

- Upstream: https://www.bamsoftware.com/git/dnstt.git (also mirrored on
  GitHub), licence GPL-3.0.
- Ported verbatim from the mihomo fork's `transport/dnstt/` (TaptapClash
  v1.0.12 behaviour), changing only the package path (it now lives under
  `protocol/slowdns/dnstt/` in this sing-box fork). No logic was changed.

DNSTT alone forwards every stream to ONE fixed TCP port on the server.
Arbitrary destinations therefore require an inner protocol on each
stream: SOCKS5 handshake (default), SSH (inner mode "ssh"), or nothing
(inner mode "fixed", stream goes straight to the server's fixed port).
UDP is NOT native to DNSTT: for inner "ssh" only, UDP is carried with
the open BadVPN udpgw framing over an SSH channel to the server's udpgw
daemon (default 127.0.0.1:7300 on the server, field "udpgw-addr").
For inner "socks"/"fixed" ListenPacket returns a clear error: there is
no spec'd UDP-over-TCP endpoint there.
