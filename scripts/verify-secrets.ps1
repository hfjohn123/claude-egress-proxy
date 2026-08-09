[CmdletBinding()]
param(
    [string] $ReleaseStagingDirectory
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
function Invoke-CheckedNative([string] $File, [string[]] $Arguments) {
    & $File @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "$File exited with $code" }
}
function Read-LockedImage([string] $Name) {
    $lock = Get-Content -Raw (Join-Path $PSScriptRoot '..\security\scanners.lock.json') | ConvertFrom-Json
    $image = [string]$lock.$Name.image
    if ($lock.schema -ne 1 -or $image -notmatch '^.+:v[0-9.]+@sha256:[a-f0-9]{64}$') { throw "invalid scanner lock for $Name" }
    return $image
}

$image = Read-LockedImage 'gitleaks'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Invoke-CheckedNative docker @('version', '--format', '{{.Server.Version}}')
Invoke-CheckedNative docker @('pull', $image)
$mount = "$root:/repo:ro"
$base = @('run', '--rm', '--read-only', '--security-opt', 'no-new-privileges', '-v', $mount, '-w', '/repo', $image, 'git', '--config', 'safe.directory=/repo', 'gitleaks', 'git', '--log-opts=--all', '--redact=100')
Invoke-CheckedNative docker $base
Invoke-CheckedNative docker @('run', '--rm', '--read-only', '--security-opt', 'no-new-privileges', '-v', $mount, '-w', '/repo', $image, 'dir', '--redact=100', '/repo')
if ($ReleaseStagingDirectory) {
    $release = (Resolve-Path $ReleaseStagingDirectory).Path
    Invoke-CheckedNative docker @('run', '--rm', '--read-only', '--security-opt', 'no-new-privileges', '-v', "$release:/release:ro", $image, 'dir', '--redact=100', '/release')
}
