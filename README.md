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

## Quick start

Download the native Linux or Windows artifact for your architecture from
[GitHub Releases](https://github.com/hfjohn123/claude-egress-proxy/releases)
and verify it against `SHA256SUMS`. Rename it to `claude-egress-proxy`
(`claude-egress-proxy.exe` on Windows) and place it on the server's `PATH`. Use
absolute paths chosen for the target platform; the deployment guides cover the
required ownership and service permissions.

1. Generate the configuration and state directory:

   ```text
   claude-egress-proxy --config <absolute-config-file> init --state-root <absolute-state-directory>
   ```

2. Copy the generated file to an operator-owned draft outside the installed
   configuration directory. Edit the draft for the public hostname, listener,
   TLS mode, resolver, public server addresses, and allowed destinations, then
   apply it through the proxy:

   ```text
   claude-egress-proxy --config <absolute-config-file> config apply --input <absolute-draft-file>
   ```

   Do not give an editor access to the installed configuration directory or
   edit the installed file directly. Follow the [home](docs/deploy-home.md) or
   [VPS](docs/deploy-vps.md) guide for DNS, TCP 443, NAT/firewall, and ACME
   requirements.

3. Validate the configuration and host network:

   ```text
   claude-egress-proxy --config <absolute-config-file> check config
   claude-egress-proxy --config <absolute-config-file> check network
   ```

4. Create a separate credential for each client device:

   ```text
   claude-egress-proxy --config <absolute-config-file> credential add --device <device-identifier>
   ```

   The credential secret is emitted once. Store it securely, never commit or
   log it, and revoke it if that device is lost or compromised.

5. Start the proxy in the foreground:

   ```text
   claude-egress-proxy --config <absolute-config-file> serve
   ```

   For persistent operation, install and start the native service instead:

   ```text
   claude-egress-proxy --config <absolute-config-file> service install
   claude-egress-proxy --config <absolute-config-file> service start
   ```

6. Configure a supported client separately with the server's HTTPS proxy
   hostname, TCP port 443, and the per-device Basic credential. See
   [client approaches](docs/client-configuration.md); the proxy does not install
   or enforce client settings.

7. If the generated loopback admin listener is enabled at its default address,
   verify local readiness:

   ```text
   claude-egress-proxy check health --address 127.0.0.1:9090
   ```

Keep the admin listener on loopback only. Read the
[security guide](docs/security.md) before exposing the public listener.

## Boundaries and operation

This is a server-only project. A deployment begins only after a request reaches
its listener. It does not install, configure, enforce, or troubleshoot client
settings, PAC acquisition, browser extensions, operating-system proxy settings,
Claude Code, Claude Desktop, Cowork, or direct-bypass prevention. Tunnel payload
bytes are opaque after CONNECT; transport metadata needed to run the service is
not opaque.

Read [configuration](docs/configuration.md), [security](docs/security.md),
[home deployment](docs/deploy-home.md), [VPS deployment](docs/deploy-vps.md),
[client approaches](docs/client-configuration.md), and the
[compatibility matrix](docs/compatibility.md) before operating a server.

## License

Apache-2.0. See [LICENSE](LICENSE).
