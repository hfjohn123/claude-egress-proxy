# Telemetry

This reference is generated from `schema/telemetry.yaml`; its labels and values are closed.

## Metrics

| Family | Type | Labels | Allowed values | HELP |
| --- | --- | --- | --- | --- |
| `claude_proxy_tls_handshakes_total` | counter | result | success, rate_limited, timeout, tls_error | Total outer TLS handshakes by terminal result. |
| `claude_proxy_authentication_total` | counter | result | challenge, valid, invalid, throttled, map_capacity, store_unavailable | Total proxy authentication outcomes by terminal result. |
| `claude_proxy_connect_total` | counter | result | established, malformed_request, port_denied, hostname_denied, address_denied, dns_failed, dial_failed, setup_timeout, credential_store_unavailable, source_bind_unavailable, self_address_state_unavailable, global_capacity, device_capacity, draining, credential_changed, client_disconnected, internal_error | Total CONNECT setup outcomes by terminal result. |
| `claude_proxy_tunnel_closes_total` | counter | result | clean, io_error, idle_timeout, absolute_lifetime, credential_revoked, shutdown_deadline | Total established tunnel closes by terminal result. |
| `claude_proxy_pac_total` | counter | result | served, disabled, not_found, prefix_rate_limited, global_rate_limited, map_capacity, capacity | Total PAC endpoint outcomes by terminal result. |
| `claude_proxy_limiter_events_total` | counter | limiter, event | tls_handshake, authentication, pac, allowed, throttled, entry_expired, map_full, saturation_overflow | Total limiter events by limiter and event. |
| `claude_proxy_reload_total` | counter | kind, result | credential, certificate, public_self, source_bind, acme, success, failure, recovered | Total runtime reload attempts by kind and result. |
| `claude_proxy_log_records_total` | counter | result | written, dropped_queue_full, dropped_sink_failed, dropped_shutdown_deadline | Total application log records by delivery result. |
| `claude_proxy_bytes_total` | counter | direction | client_to_origin, origin_to_client | Total opaque tunnel bytes by direction. |
| `claude_proxy_limiter_entries` | gauge | limiter | tls_handshake, authentication, pac | Current tracked limiter entries by limiter. |
| `claude_proxy_pre_auth_connections` | gauge |  |  | Current admitted pre-authentication connections. |
| `claude_proxy_pending_setup_reservations` | gauge |  |  | Current authenticated pending setup reservations. |
| `claude_proxy_active_tunnels` | gauge |  |  | Current established tunnels. |
| `claude_proxy_credential_generation` | gauge |  |  | Current installed credential generation, or zero when unavailable. |
| `claude_proxy_certificate_expiry_seconds` | gauge |  |  | Seconds until the active certificate expires, floored at zero. |
| `claude_proxy_setup_duration_seconds` | histogram | outcome | success, failure | CONNECT setup duration in seconds by outcome. |

Buckets: `0.01`, `0.025`, `0.05`, `0.1`, `0.25`, `0.5`, `1`, `2.5`, `5`, `10`, `15`, `+Inf`.
| `claude_proxy_tunnel_duration_seconds` | histogram | outcome | clean, error, revoked, idle_timeout, lifetime_timeout, shutdown | Established tunnel duration in seconds by outcome. |

Buckets: `1`, `5`, `30`, `60`, `300`, `900`, `1800`, `3600`, `21600`, `86400`, `604800`, `+Inf`.

## Records

Base fields: `timestamp:string:rfc3339nano_utc`, `level:string:fixed`, `event:string:closed`, `reason:string:closed`. Sensitive tunnel extension (all-or-none): `destination_hostname:string:1..253`, `device_identifier:string:1..64`, `source_prefix:string:ipv4_24_or_ipv6_64`, `duration_ms:uint64`, `bytes_client_to_origin:uint64`, `bytes_origin_to_client:uint64`. Maximum JSON size: 2047 bytes.

## Primary emission matrix

| ID | Owner | Required | Forbidden |
| --- | --- | --- | --- |
| `matrix_01_production_mapped_admission` | `admission` | limiter tls_handshake/allowed; later TLS row also applies |  |
| `matrix_02_production_overflow_admission` | `admission` | limiter tls_handshake/saturation_overflow; later TLS row also applies |  |
| `matrix_03_production_admission_denied` | `admission` | TLS rate_limited; limiter tls_handshake/throttled |  |
| `matrix_04_loopback_mapped_or_overflow_admission` | `admission` | limiter tls_handshake/allowed or tls_handshake/saturation_overflow | TLS counter |
| `matrix_05_loopback_admission_denied` | `admission` | limiter tls_handshake/throttled | TLS counter |
| `matrix_06_acme_challenge_handshake_complete` | `tls` | TLS success; pre-auth release | HTTP/auth/connect/PAC/setup/log |
| `matrix_07_no_certificate_nonchallenge_rejected` | `tls` | TLS tls_error; pre-auth release; zero HTTP bytes | request telemetry/log |
| `matrix_08_other_production_tls_terminal` | `tls` | TLS success, timeout, or tls_error matching terminal |  |
| `matrix_09_pre_handler_framework_rejection` | `framework` | no application classification | further primary emission |
| `matrix_10_public_structural_rejection` | `public_adapter` | connect malformed_request | auth/setup |
| `matrix_11_public_version_or_method_rejection` | `public_adapter` | no connect/auth/PAC emission | connect/auth/PAC |
| `matrix_12_pac_disabled_or_not_found` | `pac` | PAC disabled or not_found |  |
| `matrix_13_pac_rate_denial` | `pac` | PAC prefix_rate_limited or global_rate_limited; limiter pac/throttled |  |
| `matrix_14_pac_map_capacity_denial` | `pac` | PAC map_capacity; limiter pac/map_full |  |
| `matrix_15_pac_work_capacity_denial` | `pac` | PAC capacity | limiter event |
| `matrix_16_pac_admission_success` | `pac` | PAC served; limiter pac/allowed; before response I/O |  |
| `matrix_17_store_unavailable_before_authentication` | `authentication` | auth store_unavailable | verifier/limiter/connect/setup |
| `matrix_18_authorization_absent` | `authentication` | auth challenge | authentication-limiter event |
| `matrix_19_invalid_authentication_admitted` | `authentication` | auth invalid; limiter authentication/allowed |  |
| `matrix_20_invalid_authentication_throttled` | `authentication` | auth throttled; limiter authentication/throttled |  |
| `matrix_21_invalid_unknown_prefix_map_full` | `authentication` | auth map_capacity; limiter authentication/map_full |  |
| `matrix_22_valid_credential` | `authentication` | auth valid; create pre_admission; start setup timer | auth-limiter event |
| `matrix_23_post_valid_malformed_authority` | `setup` | connect malformed_request; setup failure |  |
| `matrix_24_other_post_valid_setup_failure` | `setup` | matching connect result; setup failure |  |
| `matrix_25_pending_to_established` | `setup` | connect established; setup success |  |
| `matrix_26_post_commit_handoff_failure` | `tunnel` | retain connect established; io_error close row |  |
| `matrix_27_established_tunnel_terminal` | `tunnel` | close result; mapped tunnel duration; both final byte increments including zero; release; tunnel_closed record |  |
| `matrix_28_admin_request_silence` | `admin` | no per-request application metric or log | per-request application metric/log |
| `matrix_29_limiter_entry_expired` | `limiter_maintenance` | limiter entry_expired for that limiter |  |
| `matrix_30_reload_success` | `reload` | reload success for kind | reload log |
| `matrix_31_reload_failure` | `reload` | reload failure; episode entry adds matching failure log |  |
| `matrix_32_reload_recovered` | `reload` | reload recovered; matching recovery log | additional success |
| `matrix_33_service_state_transition` | `service` | one matching service_state log; resulting gauges change |  |

## Deliberate silence

| ID | Owner | Required | Forbidden |
| --- | --- | --- | --- |
| `silence_01_pre_handler_framework_rejection` | `framework` | disconnect, timeout, malformed, oversized, unsupported, and framework-owned Host/framing rejection before handler entry | authentication/connect/PAC/setup/application record/header_too_large |
| `silence_02_handler_version_or_method_rejection` | `public_adapter` | handler version or method rejection | connect/auth/PAC |
| `silence_03_acme_challenge_no_request_telemetry` | `tls` | ACME challenge handshake | request telemetry |
| `silence_04_no_certificate_failure_no_request_telemetry` | `tls` | no certificate failure | request telemetry/log |
| `silence_05_admin_per_request` | `admin` | admin request | per-request application metric/log |
| `silence_06_pac_capacity_no_limiter` | `pac` | PAC capacity | limiter event |
| `silence_07_auth_challenge_no_limiter` | `authentication` | auth challenge | authentication-limiter event |
| `silence_08_valid_credential_no_auth_limiter` | `authentication` | auth valid | authentication-limiter event |
| `silence_09_unchanged_reload_poll` | `reload` | unchanged poll | reload metric/log |
| `silence_10_reload_success_no_log` | `reload` | reload success | reload log |
| `silence_11_repeated_reload_failure_no_repeat_log` | `reload` | later changed failure in same episode | repeat failure log |
| `silence_12_initial_safe_credential_absence_no_reload_log` | `reload` | initial safe credential absence | reload metric/log |

## Reload cases

| ID | Owner | Required | Forbidden |
| --- | --- | --- | --- |
| `reload_01_unchanged_poll` | `reload` | unchanged identity, metadata, or digest emits nothing | reload metric/log |
| `reload_02_first_failure` | `reload` | kind failure metric; matching failure log |  |
| `reload_03_later_changed_failure` | `reload` | failure metric | repeat failure log |
| `reload_04_first_success_after_failure` | `reload` | recovered metric; matching recovery log | success |
| `reload_05_initial_safe_absence` | `reload` | initial safe credential absence | reload metric/log |
| `reload_06_first_publication_after_absence` | `reload` | credential success; no reload log; initial-absence recovery lifecycle | reload log |
| `reload_07_scheduled_public_self_source_bind_acme_attempt` | `reload` | each scheduled public-self/source-bind check and bounded ACME try is one attempt |  |

## Lifecycle cases

| ID | Owner | Required | Forbidden |
| --- | --- | --- | --- |
| `lifecycle_01_initial_startup` | `service` | optional insecure_loopback; started; optional dangerous_custom_suffixes; optional credential_store_unavailable; initial ready or not_ready |  |
| `lifecycle_02_runtime_credential_loss` | `service` | reload/credential_failure; credential_store_unavailable; conditional not_ready |  |
| `lifecycle_03_runtime_credential_recovery` | `service` | reload/credential_recovered; credential_store_recovered; conditional ready |  |
| `lifecycle_04_initial_absence_first_publication` | `service` | credential success; credential_store_recovered; conditional ready | reload log |
| `lifecycle_05_drain` | `service` | draining; resulting not_ready |  |
| `lifecycle_06_orderly_stop` | `service` | stopped final orderly service record |  |
| `lifecycle_07_fatal_prestart` | `service` | startup_failed only | started/readiness/drain/stopped |
| `lifecycle_08_noncredential_failure_readiness` | `service` | failure log before resulting conditional not_ready |  |
| `lifecycle_09_noncredential_recovery_readiness` | `service` | recovery log before resulting conditional ready |  |
