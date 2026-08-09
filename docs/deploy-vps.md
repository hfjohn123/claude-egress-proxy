# VPS deployment

Use a provider-neutral VPS with public DNS, TCP 443 allowed by the provider and
host firewall, and a restricted state volume. Validate the generated config
before enabling a service. ACME TLS-ALPN-01 requires the DNS name and public 443
path to reach this instance.

On Linux, use the included systemd unit as a template and run under a dedicated
account with `/etc/claude-egress-proxy` and `/var/lib/claude-egress-proxy`
protected from other users. On Windows, use the supported service command and
the generated per-user state root; do not broaden its ACLs.

Compose is optional. A standalone container must persist only the protected
configuration/state mounts and should stop gracefully:

```text
docker run --stop-timeout 25 --read-only --publish 443:443 IMAGE
```

Do not publish an admin port. Do not expose insecure loopback. Keep the TLS
private key and state volume out of image layers, source control, backups shared
with untrusted users, and diagnostics pasted into tickets. Rotate a credential
before revoking its old record, then test from an external network.
