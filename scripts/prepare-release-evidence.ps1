[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScanRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$reports = @(
    @{ Source = 'amd64/grype.json'; Destination = 'grype-linux-amd64.json' },
    @{ Source = 'amd64/metadata.json'; Destination = 'metadata-linux-amd64.json' },
    @{ Source = 'arm64/grype.json'; Destination = 'grype-linux-arm64.json' },
    @{ Source = 'arm64/metadata.json'; Destination = 'metadata-linux-arm64.json' }
)

foreach ($report in $reports) {
    $source = Join-Path $ScanRoot $report.Source
    $destination = Join-Path $OutputDirectory $report.Destination
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing release scan report: $($report.Source)"
    }
    if (Test-Path -LiteralPath $destination) {
        throw "Duplicate release asset: $($report.Destination)"
    }
    Copy-Item -LiteralPath $source -Destination $destination
}
