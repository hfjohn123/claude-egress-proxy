# Prefix TTL Renewal and Capacity Design

## Goal

Prevent a continuously used source prefix from entering a 15-minute admission blackout while allowing up to 32 concurrent unauthenticated handshakes from one mapped IPv4 `/32` or IPv6 `/64` prefix.

## Confirmed Failure

`prefixMap.entry` retains an expired entry while `active > 0` so existing leases can release against the same generation. `Public.Acquire` treats that retained entry as `entryExpired` and rejects every new connection. The entry cannot be removed until all older leases release, so a long-lived browser connection can keep the source prefix unavailable after the fixed 15-minute TTL.

The TTL is an eviction deadline, not a maximum lifetime for an active source prefix. It must not become an admission-denial condition while the same limiter entry is still safely retained.

## TTL Behavior

Only `Public.Acquire` changes behavior. If the mapped prefix lookup returns `entryExpired`, the method will:

1. retain the same entry pointer and generation;
2. retain the existing token bucket and its accumulated rate-limit state;
3. set `expires` to `now + LimiterEntryTTL`;
4. continue through the ordinary existing-entry active-capacity and token-bucket checks.

No bucket reset, rate-limit refund, new map entry, or overflow admission occurs. Authentication and PAC limiter semantics remain unchanged.

## Capacity Behavior

`MappedPrefixActive` increases from 16 to 32. This limit covers concurrent pre-authentication connections sharing one mapped source prefix; it does not raise:

- global pre-authentication capacity, which remains 128;
- authenticated global tunnel capacity, which remains 256;
- per-device authenticated capacity, which remains 64;
- per-prefix start rate, which remains 5 per second;
- per-prefix burst, which remains 10;
- overflow capacity or rates.

This allows a browser and Claude Code behind the same public source to overlap more TLS handshakes without removing the global and rate-based abuse boundaries.

## Testing

A fake-clock public-admission regression will hold one lease across the TTL, advance exactly to expiry, and prove a second acquisition is admitted while preserving the same entry, generation, and bucket. Releasing both leases must return active counts to zero without underflow or leakage.

Contract tests will require `MappedPrefixActive == 32`. A capacity test will admit exactly 32 concurrent mapped-prefix leases and require the 33rd to be throttled. Existing no-refund, global-token, copied-lease, expiration cleanup, authentication, and PAC tests must remain green.

## Deployment

After full Go verification, build a new `-trimpath` Windows binary and atomically replace the stopped service executable. Do not change configuration, PAC, DDNS, metrics, or credentials. Restart and verify health, trusted TLS, public TCP 443, closed public TCP 9090, both persistent operator credentials, and a disposable credential create/use/revoke/purge cycle.

## Exclusions

Wi-Fi latency is not addressed in proxy code. The laptop is currently associated on 2.4 GHz channel 6 using 802.11n; a 100-probe router sample had 0% loss, 20.49 ms average, 202 ms p95, and 392 ms maximum latency. Moving to 5 GHz or improving router band steering is a separate network operation.
