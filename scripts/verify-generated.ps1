[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
function Invoke-CheckedNative([string] $File, [string[]] $Arguments) {
    $output = & $File @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "$File exited with $code" }
    return $output
}

Invoke-CheckedNative go @('run', './internal/tools/configgen', '-check') | Out-Null
Invoke-CheckedNative go @('run', './internal/tools/telemetrygen', '-check') | Out-Null
Invoke-CheckedNative go @('run', './internal/tools/profilegen', '-check') | Out-Null
