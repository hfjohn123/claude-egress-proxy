# Managed Configuration Apply Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fail-closed `config apply --input <draft>` workflow that validates and atomically installs configuration updates without granting editors access to the protected service directory.

**Architecture:** Extend the closed CLI grammar, add stable draft reading and candidate validation to `internal/config`, and orchestrate publication plus rollback in a focused `internal/app/config_apply.go`. Reuse `securefs.PublishOutput` for exact-policy atomic replacement; keep service lifecycle separate and preserve existing fatal diagnostics while adding non-sensitive interactive failure stages.

**Tech Stack:** Go 1.26.5, standard library, `internal/config`, `internal/securefs`, Windows exact DACL policies, table-driven Go tests.

## Global Constraints

- Keep the existing exact Windows ACL validator unchanged: foreign or inheritable ACEs remain failures.
- `instance_id` and `state_root` are immutable through apply.
- The draft is an absolute, clean, stable regular file outside the installed configuration directory.
- Apply never starts, stops, or restarts the service.
- Never emit paths, SIDs, usernames, hostnames, IP addresses, credentials, or ACL bodies in diagnostics.
- Preserve the previous installed bytes on every failure after namespace publication; distinguish rollback failure.
- Keep credentials, runtime state, local outputs, and deployment metadata out of the repository.

---

### Task 1: Closed CLI grammar and dispatch

**Files:**
- Modify: `internal/cli/parse.go`
- Modify: `internal/cli/usage.go`
- Modify: `internal/cli/parse_test.go`
- Modify: `internal/app/commands.go`
- Modify: `internal/app/run_test.go`

**Interfaces:**
- Produces: `cli.ConfigApply`, `Invocation.ConfigInput`, `cli.UsageConfigApply`, and `Dependencies.ConfigApply`.
- Consumes: existing `absolutePath`, `usageFor`, handler dispatch, and fixed-output command conventions.

- [ ] **Step 1: Add failing parser tests**

Add cases equivalent to:

```go
{"config apply", []string{"--config", absConfig, "config", "apply", "--input", absDraft}, ConfigApply, absDraft},
{"relative input", []string{"config", "apply", "--input", "draft.yaml"}, UsageConfigApply},
{"repeated input", []string{"config", "apply", "--input", absDraft, "--input", absDraft}, UsageConfigApply},
```

Assert `Invocation.ConfigInput` and add root/usage routing coverage.

- [ ] **Step 2: Run the focused tests and observe the expected failure**

Run: `go test ./internal/cli ./internal/app`

Expected: compile failures for the missing command, field, usage, and handler.

- [ ] **Step 3: Implement the minimal grammar and dispatch**

Add:

```go
const (
    // existing commands...
    ConfigApply
)

type Invocation struct {
    // existing fields...
    ConfigInput string
}

func parseConfig(args []string, goos string) (Invocation, *UsageError) {
    if len(args) != 4 || args[1] != "apply" || args[2] != "--input" || !absolutePath(args[3], goos) {
        return Invocation{}, usage(UsageConfigApply)
    }
    return Invocation{Command: ConfigApply, ConfigInput: args[3]}, nil
}
```

Use the exact usage line:

```text
usage: claude-egress-proxy [--config <absolute-installed-file>] config apply --input <absolute-draft-file>
```

Add `ConfigApply Handler` to `app.Dependencies`, production wiring, and `handler` dispatch without implementing mutation yet.

- [ ] **Step 4: Run focused and mandatory pre-commit gates**

Run, in order: `go fmt ./...`, `go mod download`, `go mod verify`, `go test ./...`, `go vet ./...`, `go list -m all`, `git status --short`.

Expected: every command exits zero; only Task 1 files are modified.

- [ ] **Step 5: Commit Task 1**

```text
feat(cli): add config apply grammar
```

---

### Task 2: Stable drafts, immutable fields, and path stages

**Files:**
- Create: `internal/config/draft.go`
- Create: `internal/config/draft_test.go`
- Modify: `internal/config/validate.go`
- Modify: `internal/config/validate_test.go`
- Modify: `internal/securefs/root.go`
- Modify: `internal/securefs/root_test.go`

**Interfaces:**
- Produces: `config.Draft`, `config.ReadDraft(string)`, `config.ValidateReplacement(*Loaded, Draft)`, `config.ErrImmutable`, `config.PathStageOf(error)`, and `Loaded.Document()`.
- Consumes: `securefs.ValidateOutput`, `ReadFile`, `Config.Decode`, retained `Loaded.StateRoot`, and `PlatformSecurityPolicies`.

- [ ] **Step 1: Add failing secure-output stage tests**

Introduce an unexported wrapped error in `securefs` and an exported query:

```go
type OutputStage uint8
const (
    OutputStageInvalid OutputStage = iota
    OutputStageParent
    OutputStageLeaf
)
func OutputStageOf(error) (OutputStage, bool)
```

Test that invalid parent/open failures report `OutputStageParent`, leaf inspection/read failures report `OutputStageLeaf`, and `errors.Is` still reaches the original error.

- [ ] **Step 2: Run the securefs test and observe failure**

Run: `go test ./internal/securefs -run 'TestValidate(Output|MutableOutput).*Stage'`

Expected: compile failure for the missing stage API.

- [ ] **Step 3: Wrap validation stages without weakening checks**

Wrap only errors returned by `ValidateOutput` and `ValidateMutableOutput`; do not change `winCheckACL`, `validateWindowsACL`, permission masks, identity comparison, or link rejection.

- [ ] **Step 4: Add failing draft and replacement tests**

Cover:

```go
draft, err := config.ReadDraft(path)
if err != nil || draft.Config().Destination().Profile() != config.ProfileAll { t.Fatal(...) }
if got := draft.Document(); !bytes.Equal(got, document) { t.Fatal(...) }
```

Also prove regular-file/stable-identity enforcement, defensive byte copies, immutable `instance_id`, immutable `state_root`, operational candidate failure, and that candidate validation reuses the retained installed state root.

- [ ] **Step 5: Implement draft and candidate validation**

Use these signatures:

```go
var ErrImmutable = errors.New("immutable configuration field changed")

type Draft struct {
    config   Config
    document []byte
}

func ReadDraft(path string) (Draft, error)
func (d Draft) Config() Config
func (d Draft) Document() []byte
func (l *Loaded) Document() []byte
func ValidateReplacement(current *Loaded, draft Draft) error
func PathStageOf(err error) (string, bool)
```

Refactor `validateOperational` into a shared helper accepting `(Config, securefs.ReadRoot, SecurityPolicies)`. `ValidateReplacement` compares immutable fields, obtains platform policies, and runs that helper against `current.StateRoot()`.

Map stages only to the fixed strings `config_directory`, `config_file`, `state_directory`, and `draft_file`.

- [ ] **Step 6: Run focused and mandatory pre-commit gates**

Run, in order: `go fmt ./...`, `go mod download`, `go mod verify`, `go test ./...`, `go vet ./...`, `go list -m all`, `git status --short`.

Expected: all pass; strict Windows ACL tests remain unchanged and passing.

- [ ] **Step 7: Commit Task 2**

```text
feat(config): validate managed replacements
```

---

### Task 3: Atomic apply orchestration and rollback

**Files:**
- Create: `internal/app/config_apply.go`
- Create: `internal/app/config_apply_test.go`
- Modify: `internal/app/commands.go`
- Modify: `internal/app/run_test.go`

**Interfaces:**
- Produces: `NewConfigApplyHandler()` and production `publishInstalledConfig(context.Context, string, []byte) (securefs.CommitBoundary, error)`.
- Consumes: Task 1 dispatch and Task 2 draft/validation APIs plus `securefs.ValidateMutableOutput` and `MutableRoot.PublishOutput`.

- [ ] **Step 1: Add failing orchestration tests**

Define injected dependencies around:

```go
type configApplyDependencies struct {
    defaults func() (config.DefaultPaths, error)
    load func(string, config.ValidationMode) (*config.Loaded, error)
    readDraft func(string) (config.Draft, error)
    validate func(*config.Loaded, config.Draft) error
    publish func(context.Context, string, []byte) (securefs.CommitBoundary, error)
}
```

Use fakes to prove: same-file/same-directory rejection, draft failure causes zero publishes, immutable/preflight failure causes zero publishes, successful apply publishes once then reloads, namespace publication followed by error triggers rollback, post-load failure triggers rollback and restored reload, and rollback failure never emits success.

- [ ] **Step 2: Run the focused test and observe failure**

Run: `go test ./internal/app -run ConfigApply`

Expected: compile failure for the missing handler and publisher.

- [ ] **Step 3: Implement publication and rollback**

`publishInstalledConfig` must:

```go
policies, err := config.PlatformSecurityPolicies()
checkout, err := config.CheckoutIdentity()
policy := policies.ConfigFile
policy.Presence = securefs.Optional
parent, name, _, err := securefs.ValidateMutableOutput(path, checkout, policies.ConfigDirectory, policy)
boundary, err := parent.PublishOutput(ctx, name, document, policy)
```

Require `NamespacePublished && TargetDurable` for success. The handler retains `current.Document()`, validates before mutation, and republishes retained bytes whenever the candidate may have reached the namespace but final operational loading fails.

Use fixed, metadata-free stderr outcomes:

```text
config apply error: draft_invalid
config apply error: immutable_change
config apply error: installed_path_security stage=<stage>
config apply error: preflight_failed
config apply error: publish_failed
config apply error: post_publish_failed rollback=restored
config apply error: rollback_failed
```

Success is exactly:

```text
state=applied
restart_required=true
```

- [ ] **Step 4: Run focused and mandatory pre-commit gates**

Run, in order: `go fmt ./...`, `go mod download`, `go mod verify`, `go test ./...`, `go vet ./...`, `go list -m all`, `git status --short`.

Expected: every gate passes and no service lifecycle command is called by apply tests.

- [ ] **Step 5: Commit Task 3**

```text
feat(config): apply updates atomically
```

---

### Task 4: Operator diagnostics, documentation, and deployment verification

**Files:**
- Modify: `internal/app/commands.go`
- Modify: `internal/app/check_config_test.go`
- Modify: `README.md`
- Modify: `docs/configuration.md`
- Modify: `integration/docs/*` only where existing command-contract tests require it

**Interfaces:**
- Produces: interactive `check config` stage detail and documented draft/apply/restart workflow.
- Consumes: `config.PathStageOf` and the fixed command output from Task 3.

- [ ] **Step 1: Add failing interactive diagnostic tests**

For `check config`, retain the canonical fatal line and append only:

```text
path_stage=config_directory
```

when the typed error exposes a stage. Verify ordinary `D004` without a stage remains byte-for-byte unchanged, so service startup diagnostics and service-specific exit-code mapping are unaffected.

- [ ] **Step 2: Run focused tests and observe failure**

Run: `go test ./internal/app ./integration/docs`

Expected: the new stage assertion and documented command checks fail.

- [ ] **Step 3: Implement interactive stage rendering and documentation**

Change only the interactive check handler's failure rendering. Update README/configuration guidance to:

```text
Copy installed config to an operator-owned draft.
Edit the draft; never grant an editor access to the installed directory.
Run config apply --input <absolute-draft-file>.
Restart the service separately and verify /readyz.
Never fix D004 by broadening ACLs.
```

Use only reserved domains and documentation address ranges in examples.

- [ ] **Step 4: Run the complete repository verification gate**

Run, in order:

```text
go fmt ./...
go mod download
go mod verify
go test ./...
go vet ./...
go list -m all
git diff --check
git status --short
```

Expected: zero failures; the diff contains no credentials, personal paths, hostnames, IP addresses, usernames, keys, logs, or runtime state.

- [ ] **Step 5: Commit Task 4**

```text
docs: add managed config update workflow
```

- [ ] **Step 6: Deploy during the authorized outage**

Build the Windows binary from the verified commit, preserve `C:\ProgramData\ClaudeEgressProxy`, replace only the installed executable, create an operator-owned draft, exercise `config apply`, start `ClaudeEgressProxy`, and verify:

```text
service=Running
readyz=200:ready
ipv4_443=reachable
```

Do not delete credentials, ACME state, certificates, admin-token state, or the installed configuration until the replacement binary has validated them.
