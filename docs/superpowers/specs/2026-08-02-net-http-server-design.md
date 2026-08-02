# `net/http` Server Architecture

**Date:** 2026-08-02  
**Status:** Approved design amendment

## Decision

Use Go's production `net/http.Server` as the HTTP/1.1 server framework. Do not
implement a request-line or header parser. Use `http.Hijacker` where the proxy
must take ownership of a connection for an exact response or a CONNECT tunnel.

The project continues to implement only its product-specific behavior:
listener admission, authentication, destination policy, DNS and dial checks,
session ownership, bounded relay, readiness, and telemetry.

## Alternatives considered

1. `net/http.Server` plus `http.Hijacker` is the selected approach. It reuses a
   mature parser and connection lifecycle while preserving access to unread
   bytes buffered after a CONNECT request.
2. General proxy packages such as goproxy or Martian are rejected. They still
   depend on `net/http` parsing and add unused HTTP forwarding and MITM
   behavior.
3. A custom HTTP/1.1 parser is rejected. Its byte-level control does not justify
   owning a security-sensitive protocol parser.

## Server boundaries

- `net/http.Server` owns request parsing, header reads, connection lifecycle,
  and framework-level rejection of malformed requests.
- Production servers enable HTTP/1.1 only. TLS ALPN never advertises HTTP/2.
- `ReadHeaderTimeout` is ten seconds.
- `MaxHeaderBytes` is configured to 16 KiB. The contract acknowledges the Go
  implementation's additional read-buffer allowance; it is not an exact
  raw-wire boundary.
- A listener wrapper acquires admission ownership before `net/http` begins
  reading a connection and releases it exactly once when ownership is not
  transferred.
- Each accepted connection serves at most one application request. Every
  handler-visible response either hijacks and closes the connection or hijacks
  and transfers it to the tunnel owner.

## Request flow

1. The listener accepts a connection and acquires the applicable public or
   admin admission lease.
2. TLS, when required, and `net/http.Server` parse the request.
3. The handler applies target-form, route, method, authentication, policy, and
   setup precedence using `http.Request` fields.
   It does not read a request body and rejects any handler-visible body,
   framing, expectation, or upgrade signal before authentication.
4. For a fixed response, the handler hijacks before any `ResponseWriter` write,
   writes the existing deterministic frame, then closes.
5. For a valid CONNECT, the handler hijacks and retains the returned
   `*bufio.ReadWriter`. Unread buffered bytes are delivered to the origin before
   subsequent client reads.
6. The existing bounded DNS, dial, commit, and opaque relay pipeline owns the
   hijacked connection after a successful transfer.

## Error contract

Requests that reach the handler retain deterministic precedence and byte-exact
response frames.

Requests rejected by `net/http` before the handler are framework-owned. They
must fail closed, close or become unusable for proxying, and never reach
authentication, destination policy, DNS, dialing, or request-result telemetry.
Their exact status, body, header order, and classification as malformed versus
oversized are not part of the product contract.

Because `net/http` normalizes some accepted HTTP syntax, the product does not
promise rejection of obsolete line folding or other syntax that the framework
accepts. Authentication values, destinations, routes, and other security-
relevant values still receive the project's strict semantic validation after
parsing.

## Testing

- Unit-test handler-visible routing, method, authentication, and policy
  precedence with typed `http.Request` fixtures.
- Use raw TCP/TLS integration tests for CONNECT, hijacking, exact fixed frames,
  one-request connections, timeouts, admission release, and coalesced bytes.
- Test parser-owned malformed and oversized inputs only for fail-closed behavior
  and absence of downstream authentication, DNS, dial, and telemetry calls.
  Do not assert framework-generated response bytes.
- Keep independent golden tests for every application-owned response frame.
- Remove custom-parser fuzz targets. Retain fuzzing for project-owned authority,
  credential, policy, and framing-value validators.
- Run race tests across admission transfer, hijack, tunnel setup, relay, and
  shutdown paths.

## Required plan and specification changes

- Replace the custom-parser portion of Task 11 with an `http.Request` adapter,
  HTTP/1.1 server configuration, hijack helper, and fixed-frame encoder.
- Update the admin and public listener tasks to enter through `net/http.Server`.
- Relax the exact 16 KiB raw boundary, pre-handler response bytes, obsolete-fold
  rejection, and parser-error telemetry requirements.
- Preserve all handler-visible security precedence, exact application frames,
  CONNECT buffered-byte handling, admission bounds, and relay guarantees.

## Non-goals

- No HTTP forward proxying for absolute-form requests.
- No TLS interception or MITM.
- No HTTP/2 or HTTP/3 serving.
- No general-purpose routing framework.
- No custom HTTP request parser.
