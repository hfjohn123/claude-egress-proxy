# Compatibility matrix

This matrix is a versioned operational record, not a product-support claim.
Unknown and failed results remain unknown/failed. Test every release against a
disposable secure proxy and proxy-side DNS capture.

| Surface | Date/version | Result | Evidence | Automation |
| --- | --- | --- | --- | --- |
| Claude Code | Not yet recorded | Unknown | Run the opt-in gate below | Opt-in release environment |
| Browser secure proxy/PAC | Not yet recorded | Unknown | Manual CONNECT/DNS evidence | Manual |
| Claude Desktop | Not yet recorded | Unknown | Manual session evidence | Manual |
| Cowork | Not yet recorded | Unknown | Manual session evidence | Manual |
| Generic API client | Not yet recorded | Unknown | Manual CONNECT/DNS evidence | Manual |

The Claude Code gate is `scripts/verify-claude-code-interop.ps1`. It records the
installed Claude Code version, uses an already authenticated disposable test
account without reading or exporting its credential, applies documented
per-process `HTTPS_PROXY`/`NO_PROXY` only, makes one bounded harmless request
through a provisioned secure proxy, verifies server-side synthetic telemetry and
DNS capture, restores the process environment, and stores only a sanitized
pass/fail/version record. It is opt-in and never belongs in ordinary public CI.
