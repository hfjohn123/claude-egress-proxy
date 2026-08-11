# Managed Configuration Apply Design

## Goal

Provide a supported way to update an installed proxy configuration without
editing the protected service copy. The command must preserve the strict path
and ACL checks that prevented an unauthorized configuration change while
avoiding the Windows editor/UAC behavior that can widen the installed
directory ACL and make the next service start fail with `D004`.

## Command Contract

Add this command:

```text
claude-egress-proxy [--config <absolute-installed-file>] config apply --input <absolute-draft-file>
```

`--config` selects the installed configuration. `--input` selects a draft that
the operator may edit outside the protected configuration directory. Both
paths must be absolute, clean paths to regular files. The draft must not be the
installed file or reside in the installed configuration directory.

On success, stdout is:

```text
state=applied
restart_required=true
```

The command never starts, stops, or restarts the service. A running service
continues using its already loaded configuration until the operator performs a
separate restart.

## Security Boundaries

The existing exact Windows ACL policy remains unchanged. In particular, the
installed directory and file must contain only the grants defined by
`PlatformSecurityPolicies`; a foreign or inheritable ACE remains a hard
failure.

The apply command treats the draft as untrusted input. It reads one
identity-pinned, regular-file snapshot with the existing configuration size
limit and rejects links, path replacement, invalid UTF-8, a BOM, aliases,
duplicate fields, and all other conditions rejected by `config.Decode`.

Two fields are immutable through apply:

- `instance_id`, because credentials, admin-token state, and ACME state are
  bound to it;
- `state_root`, because changing it is a state migration rather than a
  configuration update.

Changing either field fails before the installed namespace is mutated.

The installed configuration directory must already pass its exact security
policy. Apply does not repair or normalize an unsafe directory: mutating a
namespace after its trust boundary has failed would weaken the fail-closed
model. The command publishes the replacement file with the exact configured
file ACL, so editors never need write access to the installed directory.

## Apply Flow

1. Resolve the platform defaults and selected installed path.
2. Open and retain the installed configuration and state roots under the
   existing operational validation policy.
3. Read a stable draft snapshot from its own pinned parent directory.
4. Decode the draft and reject changes to `instance_id` or `state_root`.
5. Validate runtime dependencies represented by the draft, including
   destination policy, certificate inputs, credential/admin-token state,
   logging, source binding, and ACME state.
6. Recheck the installed directory identity and exact permissions.
7. Atomically publish the draft bytes to the installed filename through
   `securefs.PublishOutput` with `ConfigFile` policy.
8. Re-open and operationally validate the installed copy.
9. If post-publish validation fails, atomically republish the retained previous
   bytes and validate the restored copy. Report rollback failure distinctly;
   never claim success from a merely namespace-published write.

The preflight validation must share the production loader's operational
checks rather than duplicating policy logic. Refactor validation only as much
as needed to validate decoded draft bytes against the retained installed state
root.

## Diagnostics

Keep the canonical fatal diagnostics used by service startup. For interactive
`check config` and `config apply`, add a non-sensitive stage identifier when a
path-security failure occurs:

- `config_directory`
- `config_file`
- `state_directory`
- `draft_file`

Do not print absolute paths, SIDs, ACL contents, usernames, hostnames, or other
deployment metadata. Apply-specific failures must distinguish draft
validation, immutable-field rejection, preflight operational validation,
publish failure, post-publish failure, rollback success, and rollback failure.

## CLI and Component Boundaries

- `internal/cli` parses the new command and absolute input selector.
- `internal/app` owns orchestration, fixed output, rollback decisions, and
  dependency injection for tests.
- `internal/config` exposes draft decoding and shared operational validation
  without granting mutation capability.
- `internal/securefs` performs stable draft reads and atomic exact-policy
  publication. It remains the only layer that mutates protected files.
- Platform security policies continue to define the exact installed ACLs.

No service lifecycle behavior, destination matching, authentication, tunnel
handling, or credential format changes are in scope.

## Testing

Add tests that prove:

1. CLI grammar accepts exactly one absolute `--input` and rejects ambiguous,
   relative, repeated, or installed-path-equivalent input.
2. Invalid drafts and immutable-field changes leave the installed bytes and
   identity unchanged.
3. Preflight operational failures perform no publication.
4. Successful apply publishes complete bytes with exact policy and emits only
   the success contract.
5. Post-publish failure restores the previous bytes; rollback failure is
   reported without a success claim.
6. Windows publication produces the exact Administrator/service-SID file ACL.
7. A foreign or inheritable ACE on the installed directory is still rejected.
8. Interactive path-security diagnostics identify the failing stage without
   exposing path or identity metadata.
9. Existing init, check, service, credential, PAC, and serve behavior remains
   unchanged.

Run the repository's full required Go formatting, module, test, vet, and module
listing gates before commit. After the new binary passes, deploy it during the
authorized outage, apply a separately edited draft, start the service, and
verify the loopback readiness endpoint and public listener.

## Documentation

Replace instructions to edit the installed configuration directly. Document a
safe workflow: copy the installed configuration to an operator-owned draft,
edit the draft, run `config apply`, then restart and verify. State explicitly
that editors must not be granted access to the installed configuration
directory and that `D004` is not fixed by broadening ACLs.
