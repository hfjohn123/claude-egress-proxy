# VPS deployment

Use a provider-neutral VPS with public DNS, TCP 443 allowed by the provider and
host firewall, and a restricted state volume. Validate the generated config
before enabling a service. ACME TLS-ALPN-01 requires the DNS name and public 443
path to reach this instance.

On Linux, use the included systemd unit as a template and run under a dedicated
account with `/etc/claude-egress-proxy` and `/var/lib/claude-egress-proxy`
protected from other users. On Windows, use the supported service command and
the generated per-user state root; do not broaden its ACLs.

Compose is optional. For a standalone container, first initialize the named
state volume as the image's service UID, then mount the absolute configuration
read-only and the initialized state read-write:

```text
docker volume create claude-egress-proxy-state
docker run --rm --user 0:0 --read-only --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --security-opt no-new-privileges --volume claude-egress-proxy-state:/var/lib/claude-egress-proxy:rw --entrypoint /usr/local/bin/claude-egress-proxy-state-init IMAGE
docker run --stop-timeout 25 --read-only --cap-drop ALL --security-opt no-new-privileges --publish 443:8443 --volume /absolute/config.yaml:/etc/claude-egress-proxy/config.yaml:ro --volume claude-egress-proxy-state:/var/lib/claude-egress-proxy:rw IMAGE
```

The mounted container configuration must listen on `0.0.0.0:8443`; public TCP
443 is forwarded to that unprivileged internal port.

Do not publish an admin port. Do not expose insecure loopback. Keep the TLS
private key and state volume out of image layers, source control, backups shared
with untrusted users, and diagnostics pasted into tickets. Rotate a credential
before revoking its old record, then test from an external network.
