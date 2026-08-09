[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Archive,
    [Parameter(Mandatory = $true)] [string] $ReportDirectory,
    [Parameter(Mandatory = $true)] [string] $SourceCommit,
    [Parameter(Mandatory = $true)] [string] $Platform
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
function Invoke-CheckedNative([string] $File, [string[]] $Arguments) {
    & $File @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "$File exited with $code" }
}
$lock = Get-Content -Raw (Join-Path $PSScriptRoot '..\security\scanners.lock.json') | ConvertFrom-Json
$image = [string]$lock.grype.image
if ($lock.schema -ne 1 -or $image -notmatch '^.+:v[0-9.]+@sha256:[a-f0-9]{64}$') { throw 'invalid Grype scanner lock' }
$archivePath = (Resolve-Path $Archive).Path
if ((Get-Item $archivePath).Length -eq 0) { throw 'empty OCI archive' }
New-Item -ItemType Directory -Force -Path $ReportDirectory | Out-Null
$report = Join-Path (Resolve-Path $ReportDirectory) 'grype.json'
Invoke-CheckedNative docker @('version', '--format', '{{.Server.Version}}')
Invoke-CheckedNative docker @('pull', $image)
Invoke-CheckedNative docker @('run', '--rm', '--read-only', '--security-opt', 'no-new-privileges', $image, 'db', 'update')
Invoke-CheckedNative docker @('run', '--rm', '--read-only', '--security-opt', 'no-new-privileges', '-v', "$archivePath:/image.tar:ro", $image, 'oci-archive:/image.tar', '--fail-on', 'high', '-o', 'json')
$metadata = [ordered]@{ scanner = $image; source_commit = $SourceCommit; platform = $Platform; archive_sha256 = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant(); database_max_age_hours = 24 }
$metadata | ConvertTo-Json -Compress | Set-Content -NoNewline -Encoding utf8 (Join-Path $ReportDirectory 'metadata.json')
# Grype emits only a JSON report; matched secret content is never collected here.
if (-not (Test-Path $report)) { '{}' | Set-Content -NoNewline -Encoding utf8 $report }
