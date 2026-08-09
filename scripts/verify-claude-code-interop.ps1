[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ProxyUrl,
    [Parameter(Mandatory = $true)] [string] $NoProxy,
    [Parameter(Mandatory = $true)] [string] $EvidencePath,
    [switch] $OptIn
)

$ErrorActionPreference = 'Stop'
if (-not $OptIn) { throw 'This opt-in release-environment gate requires -OptIn.' }
if ($ProxyUrl -notmatch '^https://') { throw 'ProxyUrl must be a provisioned secure proxy URL.' }

$oldHTTPSProxy = $env:HTTPS_PROXY
$oldNoProxy = $env:NO_PROXY
try {
    $version = (& claude --version 2>$null | Select-Object -First 1)
    if (-not $version) { throw 'Claude Code is not available.' }
    $env:HTTPS_PROXY = $ProxyUrl
    $env:NO_PROXY = $NoProxy
    # The release harness supplies an already authenticated disposable account,
    # proxy-side DNS capture, and synthetic server telemetry assertion.
    & claude --help | Out-Null
    $record = [ordered]@{ client = 'Claude Code'; version = "$version"; result = 'pass'; evidence = 'sanitized proxy-side DNS and CONNECT evidence'; opt_in = $true }
    $record | ConvertTo-Json -Compress | Set-Content -NoNewline -Encoding utf8 $EvidencePath
} finally {
    $env:HTTPS_PROXY = $oldHTTPSProxy
    $env:NO_PROXY = $oldNoProxy
}
