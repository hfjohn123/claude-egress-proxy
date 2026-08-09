# `net/http` Server Architecture

**Date:** 2026-08-02  
**Status:** Integrated design amendment

## Decision

Use the Go 1.26.5 standard library's production `net/http.Server` for HTTP/1.x
request parsing and header reads. Use `http.Hijacker` before every
application-owned response and for each CONNECT tunnel. Do not implement a
request-line parser, header parser, or raw pre-parser.

The project continues to own only its product behavior: listener admission,
outer TLS policy, authentication, destination policy, DNS and dial checks,
session ownership, bounded relay, readiness, deterministic application frames,
and the closed telemetry schema.

## Alternatives considered

1. `net/http.Server` plus `http.Hijacker` is selected. It reuses a mature parser
   and preserves unread bytes buffered after a CONNECT request.
2. General proxy packages such as goproxy or Martian are rejected. They still
   depend on `net/http`, while adding unused forwarding and MITM behavior.
3. A custom HTTP/1.1 parser or raw validation shim is rejected. The small number
   of raw distinctions that `net/http` does not preserve are explicitly outside
   the product contract below; they do not influence the CONNECT destination.

## Listener and server boundaries

- The public listener acquires its admission lease and completes its bounded
  outer TLS handshake before returning a connection to `net/http.Server`.
  Failed TLS and ACME-only connections never enter HTTP handling. This preserves
  the existing typed TLS outcomes without forwarding raw TLS errors to the HTTP
  server or an ambient logger. Explicit insecure loopback mode and the admin
  listener return admitted plaintext connections directly.
- Each server has an explicit `http.Protocols` value with HTTP/1 enabled and
  HTTP/2 plus unencrypted HTTP/2 disabled. Public TLS advertises only
  `http/1.1`; no `TLSNextProto` HTTP/2 handler is installed, and an ACME
  challenge is selected and completed before HTTP serving.
  Because Go's HTTP/1 setting includes HTTP/1.0, the first handler decision is
  an exact `ProtoMajor == 1 && ProtoMinor == 1` gate. A handler-visible HTTP/1.0,
  other HTTP/1.x minor, or `PRI * HTTP/2.0` request receives the application
  `505` frame and closes.
- `ReadHeaderTimeout` and `WriteTimeout` are ten seconds,
  `MaxHeaderBytes` is `16 << 10`, and `ReadTimeout` plus `IdleTimeout` are zero.
  Keep-alives are disabled before serving and
  `DisableGeneralOptionsHandler` is true so `OPTIONS *` reaches normal handler
  precedence. `MaxHeaderBytes` is a framework
  configuration value, not an exact raw-wire ceiling: the Go implementation may
  consume its documented read-buffer allowance beyond that value. Post-hijack
  code never relies on `WriteTimeout` because Go clears it during the transfer.
- Every server sets a non-nil `ErrorLog` backed by `io.Discard`. Framework log
  strings, including remote addresses, TLS errors, panic values, and stacks,
  are never copied to application telemetry or process stderr. Product-owned
  failures are reported separately through static typed outcomes.
- An admitted connection is wrapped in one close-once lease owner. Framework
  close releases it unless the hijack helper transfers it to a registered
  application owner. Every accepted connection serves at most one application
  request.

## Normalization and adapter contract

`net/http` owns request-line and header syntax. Inputs it rejects before the
handler are framework-owned. Syntax it accepts and normalizes, including
obsolete line folding, is accepted by the product unless a handler-visible
semantic rule below rejects it.

For CONNECT, immutable `Request.RequestURI` is the sole destination input;
neither `Request.Host`, `Request.URL.Host`, nor a raw `Host` field is used for
routing, authentication, or policy. Go rejects malformed or duplicate Host
fields before the handler. For an otherwise accepted CONNECT, it derives the
normalized Host fields from the target and removes the raw header, so the
handler cannot distinguish an absent field from one conflicting field. Those
two raw distinctions are deliberately not part of the v1 contract. Tests must
prove that changing or omitting one raw `Host` cannot change the selected
destination or bypass authority policy.

After the exact version gate, one adapter performs the common handler-visible
body, framing, expectation, and upgrade checks before routing or
authentication. Header authentication remains listener-scoped:

- On the public listener only,
  `Request.Header.Values("Proxy-Authorization")` must contain zero or one field
  value before target routing or authentication. More than one is the
  application `400` path. The single value, when present, is copied to a bounded
  credential value and immediately removed from the request header map before
  being passed unchanged to the strict Basic verifier; `Header.Get` is not used
  for multiplicity decisions. `Proxy-Authorization` has no routing or
  authentication meaning on the admin listener and cannot change an admin
  result. The admin metrics route applies the copy-and-remove rule to
  `Authorization` only after route and method precedence; duplicate,
  present-empty, malformed, and wrong values share its uniform `401`.
- Presence of canonical `Content-Length` in the header map is rejected even for
  an empty or zero value. Equal duplicate lengths may have been collapsed by Go,
  but the surviving field is still rejected. A non-empty
  `Request.TransferEncoding`, any handler-visible `Expect`, an `Upgrade` field,
  a `Connection` token naming `upgrade`, a non-`NoBody` body, or another
  handler-visible body/upgrade signal is also rejected. Conflicting lengths and
  other framing that Go rejects earlier remain framework-owned.
- The adapter never reads `Request.Body`, never uses `Request.Host` or
  `Request.URL.Host` as a CONNECT authority, and never reconstructs raw syntax
  that the framework discarded.

The handler then applies target form, exact route and enabled state, method,
authentication, destination policy, and setup precedence. Semantic authority
validation remains after successful proxy authentication.

## Hijack and ownership contract

All handler-visible responses use one hijack helper. Before calling `Hijack`,
the helper registers a handoff-pending application owner with the session
coordinator under the same drain serialization used for setup and tunnel
commit. A failed hijack rolls back that owner and leaves framework cleanup to
close the connection. A successful hijack transfers the admission lease and
attaches the returned `net.Conn` and `*bufio.ReadWriter` to the registered owner.

Go 1.26.5 clears connection deadlines during hijack, while the public Hijacker
contract does not guarantee any inherited deadline state. Therefore, after a
successful hijack and before any other potentially blocking operation, the
helper overwrites inherited state with the next application deadline and checks
the setter result; failure closes and releases the owner:

- A fixed response gets a ten-second write deadline, is flushed completely,
  then closes and releases its owner.
- An authenticated CONNECT entering setup gets the absolute remaining setup
  deadline. DNS, dial, cancellation, and any setup failure share that budget.
- Before a setup-failure frame or the successful CONNECT frame, the owner
  installs the ten-second response-write deadline. The CONNECT frame is flushed
  before relay handoff.
- Relay handoff replaces the setup/write deadline with the relay's idle and
  optional absolute-lifetime management. No path clears a deadline without
  installing its next bounded owner.

Unread bytes in the returned buffered reader are delivered to the origin before
subsequent reads from the client. A recovery boundary inside the application
handler closes and releases any registered or hijacked owner on panic; it emits
no panic value or stack. The framework's discard logger is a final containment
boundary, not the owner of application cleanup.

`http.Server.Shutdown` owns only non-hijacked framework connections and handlers.
Graceful shutdown first enters coordinator drain: it rejects new setup/tunnel
handoffs and commits but still permits a handler admitted before drain to
register one bounded fixed-response owner for its already-selected terminal
response. It cancels pending setups, invokes both HTTP servers' `Shutdown`
concurrently, and waits for their handlers plus fixed-response and tunnel owners.
At the configured deadline it calls `Server.Close`, force-closes every remaining
hijacked owner, and waits for exactly-once release. `http.ErrServerClosed` is a
normal shutdown result; completion never assumes `Shutdown` waited for hijacked
connections.

## Error and telemetry contract

Requests that reach the handler retain deterministic precedence and byte-exact
application response frames. Handler-visible version, structural, routing,
method, authentication, policy, and setup outcomes use the existing typed
application contract.

Requests rejected by `net/http` before the handler are framework-owned. They
must fail closed, close or become unusable for proxying, and never reach routing,
authentication, destination policy, DNS, dialing, or request-result telemetry.
Their exact status, body, header order, malformed-versus-oversized
classification, and acceptance of normalized legacy syntax are not product
contracts. In particular, v1 does not promise an exact 16 KiB raw boundary,
application `400`/`431` bytes for framework failures, parser-error telemetry,
obsolete-fold rejection, or raw CONNECT-Host consistency checks.

The listener-owned TLS counters remain available because TLS admission completes
before HTTP handoff. Framework logging is always discarded; closed application
metrics and logs remain the only observable telemetry surface.

## Testing

- Unit-test handler-visible version, normalized structural checks, target form,
  routing, method, authentication, and policy precedence using typed
  `http.Request` fixtures. These tests may not stand in for parser-boundary
  behavior.
- Use raw TCP/TLS integration cases for HTTP/1.0, other HTTP/1.x minors,
  `PRI * HTTP/2.0`, `OPTIONS *`, malformed and oversized headers, absent or one
  conflicting raw Host, framework-rejected duplicate/malformed Host, duplicate
  public Proxy-Authorization, irrelevant duplicate Proxy-Authorization on admin
  health/readiness/metrics, `Content-Length: 0`, equal
  and conflicting duplicate lengths, Content-Length plus Transfer-Encoding,
  Expect, Upgrade, accepted folding and line variants, ALPN, one-request
  connections, and coalesced post-CONNECT bytes.
- For every raw case, assert whether the handler is reached; whether bytes are
  framework- or application-owned; the selected destination when applicable;
  zero forbidden authentication, policy, DNS, dial, and telemetry calls; and
  final close or tunnel ownership. Do not assert framework-generated response
  bytes.
- Inject remote-address, raw-error, and panic sentinels into TLS failure,
  framework rejection, and handler-panic cases. Capture every configured log
  sink and process stderr and require that none contains a sentinel, stack, or
  raw framework message.
- Race hijack against drain and cancellation at handoff-pending, post-hijack/
  pre-deadline, fixed-write, setup, CONNECT-write, and relay-transfer barriers.
  Assert the applicable deadline is installed before blocking I/O, every owner
  releases exactly once, graceful shutdown waits for registered hijacked owners,
  and force-close produces final EOF.
- Keep independent golden tests for every application-owned response frame.
  Retain fuzzing for product-owned authority, credential, policy, and framing-
  value validators; do not recreate a custom HTTP parser fuzz target.

## Canonical integration

The canonical specification and implementation plan are revised with this
amendment as one change set. They replace custom-parser construction, exact
parser-error bytes/telemetry, and raw Host invariants with the framework,
adapter, ownership, privacy, and raw integration contracts above. The plan pins
the revised specification hash before HTTP-server implementation resumes.

## Non-goals

- No HTTP forward proxying for absolute-form requests.
- No TLS interception or MITM.
- No HTTP/2 or HTTP/3 serving.
- No general-purpose routing framework.
- No custom HTTP request parser or raw validation shim.
