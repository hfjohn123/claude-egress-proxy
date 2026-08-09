[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Hostname,
    [Parameter(Mandatory = $true)] [string] $StateRoot,
    [switch] $OptIn
)

$ErrorActionPreference = 'Stop'
if (-not $OptIn) { throw 'real ACME staging is opt-in and never ordinary CI.' }
if ($Hostname -notmatch '\.test$' -and $Hostname -notmatch '\.invalid$') { throw 'use an explicitly provisioned disposable hostname.' }
if (Test-Path $StateRoot) { throw 'ACME state root must be empty and temporary.' }
New-Item -ItemType Directory -Path $StateRoot | Out-Null
try {
    # Release environment must prove positive DNS and public TCP 443 before invocation.
    throw 'ACME staging harness must supply public DNS and TCP 443 checks.'
} finally {
    Remove-Item -LiteralPath $StateRoot -Force -Recurse -ErrorAction SilentlyContinue
}
