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

| ID | Owner | Emission |
| --- | --- | --- |
| `matrix_01_production_mapped_admission` | `admission` |  |
| `matrix_02_production_overflow_admission` | `admission` |  |
| `matrix_03_production_admission_denied` | `admission` |  |
| `matrix_04_loopback_mapped_or_overflow_admission` | `admission` |  |
| `matrix_05_loopback_admission_denied` | `admission` |  |
| `matrix_06_acme_challenge_handshake_complete` | `tls` |  |
| `matrix_07_no_certificate_nonchallenge_rejected` | `tls` |  |
| `matrix_08_other_production_tls_terminal` | `tls` |  |
| `matrix_09_pre_handler_framework_rejection` | `framework` |  |
| `matrix_10_public_structural_rejection` | `public_adapter` |  |
| `matrix_11_public_version_or_method_rejection` | `public_adapter` |  |
| `matrix_12_pac_disabled_or_not_found` | `pac` |  |
| `matrix_13_pac_rate_denial` | `pac` |  |
| `matrix_14_pac_map_capacity_denial` | `pac` |  |
| `matrix_15_pac_work_capacity_denial` | `pac` |  |
| `matrix_16_pac_admission_success` | `pac` |  |
| `matrix_17_store_unavailable_before_authentication` | `authentication` |  |
| `matrix_18_authorization_absent` | `authentication` |  |
| `matrix_19_invalid_authentication_admitted` | `authentication` |  |
| `matrix_20_invalid_authentication_throttled` | `authentication` |  |
| `matrix_21_invalid_unknown_prefix_map_full` | `authentication` |  |
| `matrix_22_valid_credential` | `authentication` |  |
| `matrix_23_post_valid_malformed_authority` | `setup` |  |
| `matrix_24_other_post_valid_setup_failure` | `setup` |  |
| `matrix_25_pending_to_established` | `setup` |  |
| `matrix_26_post_commit_handoff_failure` | `tunnel` |  |
| `matrix_27_established_tunnel_terminal` | `tunnel` |  |
| `matrix_28_admin_request_silence` | `admin` |  |
| `matrix_29_limiter_entry_expired` | `limiter_maintenance` |  |
| `matrix_30_reload_success` | `reload` |  |
| `matrix_31_reload_failure` | `reload` |  |
| `matrix_32_reload_recovered` | `reload` |  |
| `matrix_33_service_state_transition` | `service` |  |

## Deliberate silence

| ID | Owner | Emission |
| --- | --- | --- |
| `silence_01_pre_handler_framework_rejection` | `framework` |  |
| `silence_02_handler_version_or_method_rejection` | `public_adapter` |  |
| `silence_03_acme_challenge_no_request_telemetry` | `tls` |  |
| `silence_04_no_certificate_failure_no_request_telemetry` | `tls` |  |
| `silence_05_admin_per_request` | `admin` |  |
| `silence_06_pac_capacity_no_limiter` | `pac` |  |
| `silence_07_auth_challenge_no_limiter` | `authentication` |  |
| `silence_08_valid_credential_no_auth_limiter` | `authentication` |  |
| `silence_09_unchanged_reload_poll` | `reload` |  |
| `silence_10_reload_success_no_log` | `reload` |  |
| `silence_11_repeated_reload_failure_no_repeat_log` | `reload` |  |
| `silence_12_initial_safe_credential_absence_no_reload_log` | `reload` |  |

## Reload cases

- `reload_01_unchanged_poll`
- `reload_02_first_failure`
- `reload_03_later_changed_failure`
- `reload_04_first_success_after_failure`
- `reload_05_initial_safe_absence`
- `reload_06_first_publication_after_absence`
- `reload_07_scheduled_public_self_source_bind_acme_attempt`

## Lifecycle cases

- `lifecycle_01_initial_startup`
- `lifecycle_02_runtime_credential_loss`
- `lifecycle_03_runtime_credential_recovery`
- `lifecycle_04_initial_absence_first_publication`
- `lifecycle_05_drain`
- `lifecycle_06_orderly_stop`
- `lifecycle_07_fatal_prestart`
- `lifecycle_08_noncredential_failure_readiness`
- `lifecycle_09_noncredential_recovery_readiness`
