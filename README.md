# Claude Egress Proxy

`claude-egress-proxy` is a pre-release, server-only egress proxy for a closed,
generated policy. It carries authenticated CONNECT tunnels as byte-opaque
traffic after connection establishment.

This is an unofficial project. It is not affiliated with, endorsed by, or
sponsored by Anthropic. It does not provide a client, browser extension, local
agent, VPN, driver, PAC installer, or traffic-enforcement feature.

The public v1 transport is TLS 1.2+ with one strict HTTP/1.1 request. Public
proxying accepts authenticated authority-form CONNECT only to TCP port 443; it
resolves A records and dials IPv4 TCP only. HTTP/2 outer proxying, UDP, QUIC,
SOCKS, and TLS interception are out of scope.

Do not use this pre-release in production. The repository intentionally
contains no credentials, private endpoints, personal paths, or runtime state.

## License

Apache-2.0. See [LICENSE](LICENSE).
