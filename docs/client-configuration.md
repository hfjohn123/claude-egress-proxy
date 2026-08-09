# Client configuration approaches

This document describes approaches only; it does not implement or install a
client. Client behavior can change and any client may bypass the proxy. The
server cannot prevent that bypass.

Claude Code may honor its documented per-process `HTTPS_PROXY` and `NO_PROXY`
environment variables where supported. Use proxy authentication only with a
disposable per-user credential, and let DNS happen proxy-side rather than
resolving an allowed destination locally. Proxy use can affect login, updates,
extensions, and features that do not use the documented proxy path. Consult the
client's current documentation before relying on it.

Browsers vary: secure-proxy/PAC support, authentication prompts, DNS behavior,
and bypass rules are browser and platform choices. A generated PAC is merely a
profile; acquisition and enforcement are outside this project. Generic API
clients commonly support an HTTPS proxy but must be tested per client.

Claude Desktop and Cowork have no project-provided routing mechanism. Their
current status is manual compatibility testing only, not a support promise.

For local testing, create a disposable per-user state root and credential. A
plaintext environment variable or command history entry can disclose that
credential: remove it after the bounded test, revoke the credential, and delete
the disposable state root using your platform's recoverable cleanup procedure.
