# Windows Update Restart Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Configure the laptop to require operator action before Windows Update installation and prevent surprise update restarts while retaining updates and automatic proxy/DDNS recovery.

**Architecture:** Two focused PowerShell scripts own apply and rollback. The apply script snapshots the exact Windows Update policy subtree, writes documented DWORD policies, and verifies update, power, proxy, and DDNS state without rebooting. The rollback script removes the deployed subtree and restores the snapshot when one existed.

**Tech Stack:** Windows PowerShell 5.1, Windows registry policy keys, `reg.exe`, ScheduledTasks, `powercfg`, existing proxy CLI.

## Global Constraints

- Do not disable Windows Update or its services.
- Do not initiate, schedule, or request a reboot.
- Apply `AUOptions=2`, `NoAutoRebootWithLoggedOnUsers=1`, `AlwaysAutoRebootAtScheduledTime=0`, `SetActiveHours=1`, `ActiveHoursStart=6`, and `ActiveHoursEnd=0` as DWORD values.
- Preserve a timestamped rollback snapshot under `work/deployment/backups`.
- Require proxy service automatic/running/healthy and DDNS SYSTEM/boot/PT5M after mutation.
- Treat Windows Home policy enforcement as best effort; report the limitation without claiming an absolute guarantee.

---

### Task 1: Tested apply and rollback scripts

**Files:**
- Create: `work/deployment/WindowsUpdateServerPolicy.Tests.ps1`
- Create: `work/deployment/Apply-WindowsUpdateServerPolicy.ps1`
- Create: `work/deployment/Rollback-WindowsUpdateServerPolicy.ps1`

**Interfaces:**
- Apply consumes the local Administrator token and current registry/service/task state; it produces a closed status report plus a rollback manifest and optional `.reg` export.
- Rollback consumes the latest manifest path supplied through `-ManifestPath`; it restores only the Windows Update policy subtree and does not reboot.

- [ ] **Step 1: Write the failing static/safety test**

Create a Windows PowerShell test that requires both production scripts; asserts all six policy names and exact values; requires `reg.exe export`, manifest creation, exact rollback scoping, proxy health, DDNS SYSTEM/boot/PT5M, pending-reboot and power checks; and rejects `Restart-Computer`, `shutdown.exe`, Windows Update service disable/stop, and wildcard registry deletion.

- [ ] **Step 2: Run the test to verify RED**

Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File work\deployment\WindowsUpdateServerPolicy.Tests.ps1
```

Expected: exit 1 with `missing apply script`.

- [ ] **Step 3: Implement minimal apply and rollback scripts**

Apply writes these exact values:

```powershell
Set-ItemProperty $windowsUpdateKey SetActiveHours 1 -Type DWord
Set-ItemProperty $windowsUpdateKey ActiveHoursStart 6 -Type DWord
Set-ItemProperty $windowsUpdateKey ActiveHoursEnd 0 -Type DWord
Set-ItemProperty $auKey AUOptions 2 -Type DWord
Set-ItemProperty $auKey NoAutoRebootWithLoggedOnUsers 1 -Type DWord
Set-ItemProperty $auKey AlwaysAutoRebootAtScheduledTime 0 -Type DWord
```

The manifest records `policy_key_existed`, optional export path, and UTC creation timestamp. Verification emits only closed fields and the manifest path. Rollback requires elevation, validates the manifest is under the fixed backup directory, removes the exact policy subtree, imports the snapshot only when it existed, and emits closed fields.

- [ ] **Step 4: Run tests and parser checks to verify GREEN**

Run the test from Step 2 and parse both scripts with `[Management.Automation.Language.Parser]::ParseFile`. Expected: exit 0, `result=ok tests=windows-update-server-policy`, and no parser errors.

- [ ] **Step 5: Commit scripts**

```powershell
git add work/deployment/WindowsUpdateServerPolicy.Tests.ps1 work/deployment/Apply-WindowsUpdateServerPolicy.ps1 work/deployment/Rollback-WindowsUpdateServerPolicy.ps1
git commit -m "ops: prevent unattended Windows update restarts"
```

The deployment scripts live outside the source worktree, so record their verified hashes in the task report instead of adding them to the upstream repository commit.

### Task 2: Apply and independently verify policy

**Files:**
- Runtime create: `work/deployment/backups/windows-update-policy-<UTC>.json`
- Runtime create when needed: `work/deployment/backups/windows-update-policy-<UTC>.reg`

**Interfaces:**
- Consumes the scripts from Task 1.
- Produces exact registry policy values and a verified rollback artifact.

- [ ] **Step 1: Run apply as the current Administrator**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File work\deployment\Apply-WindowsUpdateServerPolicy.ps1
```

Expected: `result=ok stage=policy-applied`, all six policy fields `yes`, update services enabled, no WU/CBS pending reboot, sleep/hibernate disabled, proxy recovery/health yes, DDNS recovery yes, and `reboot-initiated=no`.

- [ ] **Step 2: Independently read effective state**

Read the six registry DWORDs directly, query `wuauserv` start mode without changing it, query pending restart markers, query AC/DC sleep and hibernate with `powercfg`, check `ClaudeEgressProxy` automatic/running/health, and inspect the DDNS task XML for SYSTEM, boot, and PT5M.

- [ ] **Step 3: Verify rollback artifacts and script hashes**

Require the manifest referenced by apply output to exist under the fixed backup directory, parse as JSON, and hash both production scripts and the manifest. Do not execute rollback.

- [ ] **Step 4: Record final evidence**

Report the exact closed verification fields, rollback-manifest link, and the Windows Home enforcement limitation. Do not claim an absolute reboot guarantee and do not reboot.
