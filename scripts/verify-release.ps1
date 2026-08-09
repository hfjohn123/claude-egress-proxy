[CmdletBinding()]
param(
    [string] $Archive,
    [string] $Platform = 'linux/amd64',
    [string] $ReportDirectory = 'out/release-scan'
)

$ErrorActionPreference = 'Stop'
if (-not $Archive) { throw 'release verification requires an OCI archive produced by the release build.' }
$commit = git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'git rev-parse failed' }
& (Join-Path $PSScriptRoot 'verify-container.ps1') -Archive $Archive -ReportDirectory $ReportDirectory -SourceCommit $commit -Platform $Platform
if ($LASTEXITCODE -ne 0) { throw 'container scan failed' }
