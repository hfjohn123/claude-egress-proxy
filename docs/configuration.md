# Configuration and state

Generate a starter file with `claude-egress-proxy init`; do not hand-copy a
credential or profile into a URL. Validate it with `claude-egress-proxy check
config`, then start it with `claude-egress-proxy serve`. `claude-egress-proxy
pac --output <absolute-file>` writes a generated profile; the server neither
distributes nor enforces that profile.

The generated configuration has `format_version`, `instance_id`, and
`state_root`; `public_listener.addresses` and `public_listener.pac_enabled`;
`admin_listener.enabled` and its loopback address when enabled; `tls.mode` and
mode-specific hostname/certificate settings; `resolver.mode` and resolver
address; `public_self_ipv4s`; destination `profile`, `exact_hosts`, `suffixes`,
and `dangerous_custom_suffixes`; logging `sink` and `sensitive_metadata`; and
metrics `enabled`.

The three capacity/lifetime knobs are `per_device_capacity`,
`absolute_tunnel_lifetime`, and `graceful_shutdown_drain`. Keep the generated
defaults unless you have measured a need. `absolute_tunnel_lifetime: disabled`
is intentional, and drain time bounds graceful shutdown rather than client
routing.

Use only the generated config/profile references and absolute paths accepted by
the CLI. On Linux the normal config root is `/etc/claude-egress-proxy` and state
root is `/var/lib/claude-egress-proxy`; on Windows the generated per-user root
is used. The service validates safe roots, regular files, ownership, modes, and
ACLs. Do not place state inside a source checkout or shared/synchronized folder.

Credentials are server state: add a device credential, retain the one-time
secret only where the client needs it, then revoke or purge by record ID. Rotate
the admin token with `claude-egress-proxy admin-token rotate`; keep the admin
listener loopback-only. A generated PAC/profile is not a credential.

See [security](security.md) and [release checklist](release-checklist.md).
