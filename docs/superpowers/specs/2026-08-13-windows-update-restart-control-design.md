# Windows Update Restart Control Design

## Objective

Keep the Windows laptop available as a proxy server by preventing unattended
Windows Update installation and minimizing automatic restart paths, without
disabling Windows Update or weakening the installed proxy and DDNS recovery.

## Current State

- The machine runs Windows client Home, build 26100.
- No Windows Update policy values currently control download, installation, or
  restart behavior.
- Windows Update and Component Based Servicing report no pending restart.
- Sleep and hibernation are disabled on AC and battery.
- `ClaudeEgressProxy` is an automatic Windows service.
- The DDNS updater runs as SYSTEM with boot and five-minute triggers.

## Policy Design

The deployment will create only the documented Windows Update policy keys:

- `AUOptions=2`: notify before downloading and installing updates.
- `NoAutoRebootWithLoggedOnUsers=1`: prevent an automatic restart while a user
  is signed in, as defense in depth.
- `AlwaysAutoRebootAtScheduledTime=0`: disable the legacy scheduled forced
  restart path where Windows honors it.
- `SetActiveHours=1`, `ActiveHoursStart=6`, and `ActiveHoursEnd=0`: protect the
  maximum 18-hour window from 06:00 through midnight.

Windows Update remains enabled. The operator initiates update installation and
restart during a maintenance window. Windows Home may not honor every
enterprise policy consistently, so this design reduces surprise restart risk
but does not claim an absolute platform guarantee.

## Safety and Rollback

Before mutation, the installer exports the existing Windows Update policy
registry subtree to a timestamped file under the deployment workspace. It does
not restart Windows, stop Windows Update, or change update services. A rollback
script restores the exported policy state or removes only values introduced by
this deployment when no prior subtree existed.

## Verification

After applying the policy, verification requires:

1. Every intended registry value exists with the exact DWORD value.
2. Windows Update and CBS still have no restart-pending marker.
3. Sleep and hibernation remain disabled on AC and battery.
4. `ClaudeEgressProxy` remains automatic and running, and its health check
   passes.
5. The DDNS task remains SYSTEM-owned with a boot trigger and PT5M repetition.

No controlled reboot is performed as part of this change.
