[CmdletBinding()]
param(
    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    [Console]::Error.WriteLine("eventlog resource build: $Message")
    exit 1
}

function Get-SdkTools {
    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ([string]::IsNullOrWhiteSpace($programFilesX86)) {
        return $null
    }

    $binRoot = Join-Path $programFilesX86 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $binRoot -PathType Container)) {
        return $null
    }

    $versions = @(Get-ChildItem -LiteralPath $binRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object -Property Name -Descending)
    foreach ($version in $versions) {
        foreach ($hostArchitecture in @('x64', 'x86', 'arm64')) {
            $toolDirectory = Join-Path $version.FullName $hostArchitecture
            $mc = Join-Path $toolDirectory 'mc.exe'
            $rc = Join-Path $toolDirectory 'rc.exe'
            if ((Test-Path -LiteralPath $mc -PathType Leaf) -and (Test-Path -LiteralPath $rc -PathType Leaf)) {
                return [pscustomobject]@{ Mc = $mc; Rc = $rc }
            }
        }
    }
    return $null
}

function Get-CvtResTool {
    $commands = @(Get-Command cvtres.exe -CommandType Application -ErrorAction SilentlyContinue)
    if ($commands.Count -gt 0) {
        return ($commands | Sort-Object -Property Source | Select-Object -First 1).Source
    }

    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ([string]::IsNullOrWhiteSpace($programFilesX86)) {
        return $null
    }
    $visualStudioRoot = Join-Path $programFilesX86 'Microsoft Visual Studio'
    if (-not (Test-Path -LiteralPath $visualStudioRoot -PathType Container)) {
        return $null
    }

    $candidates = @(Get-ChildItem -LiteralPath $visualStudioRoot -Recurse -File -Filter 'cvtres.exe' -ErrorAction SilentlyContinue |
        Sort-Object -Property FullName)
    if ($candidates.Count -eq 0) {
        return $null
    }
    return $candidates[0].FullName
}

function Invoke-Tool([string]$Tool, [string[]]$Arguments) {
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Tool @Arguments *> $null
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($exitCode -ne 0) {
        Fail 'compatible Windows SDK tools failed'
    }
}

function Set-UInt16([byte[]]$Bytes, [int]$Offset, [uint16]$Value) {
    [Buffer]::BlockCopy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 2)
}

function Set-UInt32([byte[]]$Bytes, [int]$Offset, [uint32]$Value) {
    [Buffer]::BlockCopy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 4)
}

function Remove-CoffDebugMetadata([string]$Path, [uint16]$Machine) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 140 -or [BitConverter]::ToUInt16($bytes, 0) -ne $Machine -or
        [BitConverter]::ToUInt16($bytes, 2) -ne 3) {
        Fail 'compatible Windows SDK tools produced an invalid resource object'
    }
    $debugHeader = 20
    $debugName = [Text.Encoding]::ASCII.GetString($bytes, $debugHeader, 8).TrimEnd([char]0)
    $debugSize = [BitConverter]::ToUInt32($bytes, $debugHeader + 16)
    $debugStart = [BitConverter]::ToUInt32($bytes, $debugHeader + 20)
    if ($debugName -ne '.debug$S' -or $debugStart -ne 140 -or $debugSize -eq 0 -or
        $debugStart + $debugSize -gt $bytes.Length) {
        Fail 'compatible Windows SDK tools produced an incompatible resource object'
    }

    $removedByteCount = 40 + [int]$debugSize
    $result = New-Object byte[] ($bytes.Length - $removedByteCount)
    [Buffer]::BlockCopy($bytes, 0, $result, 0, 20)
    [Buffer]::BlockCopy($bytes, 60, $result, 20, 80)
    [Buffer]::BlockCopy($bytes, [int]($debugStart + $debugSize), $result, 100,
        $bytes.Length - [int]($debugStart + $debugSize))
    Set-UInt16 $result 2 2
    Set-UInt32 $result 4 0
    $symbolTable = [BitConverter]::ToUInt32($bytes, 8)
    if ($symbolTable -lt ($debugStart + $debugSize)) {
        Fail 'compatible Windows SDK tools produced an incompatible resource object'
    }
    Set-UInt32 $result 8 ([uint32]($symbolTable - $removedByteCount))

    foreach ($sectionIndex in @(0, 1)) {
        $headerOffset = 20 + (40 * $sectionIndex)
        foreach ($fieldOffset in @(20, 24)) {
            $value = [BitConverter]::ToUInt32($result, $headerOffset + $fieldOffset)
            if ($value -ne 0) {
                if ($value -lt ($debugStart + $debugSize)) {
                    Fail 'compatible Windows SDK tools produced an incompatible resource object'
                }
                Set-UInt32 $result ($headerOffset + $fieldOffset) ([uint32]($value - $removedByteCount))
            }
        }
    }

    $symbolOffset = [BitConverter]::ToUInt32($result, 8)
    $symbolCount = [BitConverter]::ToUInt32($result, 12)
    if ($symbolCount -ne 9 -or $symbolOffset + (18 * $symbolCount) + 4 -gt $result.Length -or
        [Text.Encoding]::ASCII.GetString($result, [int]$symbolOffset + 36, 8).TrimEnd([char]0) -ne '.debug$S') {
        Fail 'compatible Windows SDK tools produced an incompatible resource object'
    }
    foreach ($sectionIndex in @(0, 1)) {
        $headerOffset = 20 + (40 * $sectionIndex)
        $relocationOffset = [BitConverter]::ToUInt32($result, $headerOffset + 24)
        $relocationCount = [BitConverter]::ToUInt16($result, $headerOffset + 32)
        for ($relocationIndex = 0; $relocationIndex -lt $relocationCount; $relocationIndex++) {
            $relocation = [int]$relocationOffset + (10 * $relocationIndex)
            if ($relocation + 10 -gt $result.Length) {
                Fail 'compatible Windows SDK tools produced an incompatible resource object'
            }
            $symbolIndex = [BitConverter]::ToUInt32($result, $relocation + 4)
            if ($symbolIndex -lt 4) {
                Fail 'compatible Windows SDK tools produced an incompatible resource object'
            }
            Set-UInt32 $result ($relocation + 4) ([uint32]($symbolIndex - 4))
        }
    }

    $metadataSymbolBytes = 18 * 4
    $stripped = New-Object byte[] ($result.Length - $metadataSymbolBytes)
    [Buffer]::BlockCopy($result, 0, $stripped, 0, [int]$symbolOffset)
    [Buffer]::BlockCopy($result, [int]$symbolOffset + $metadataSymbolBytes, $stripped, [int]$symbolOffset,
        $result.Length - [int]$symbolOffset - $metadataSymbolBytes)
    $result = $stripped
    Set-UInt32 $result 12 5

    $symbolIndex = 0
    $symbolCursor = [int]$symbolOffset
    while ($symbolIndex -lt 5) {
        if ($symbolCursor + 18 -gt $result.Length) {
            Fail 'compatible Windows SDK tools produced an incompatible resource object'
        }
        $sectionNumber = [BitConverter]::ToInt16($result, $symbolCursor + 12)
        if ($sectionNumber -gt 1) {
            [Buffer]::BlockCopy([BitConverter]::GetBytes([int16]($sectionNumber - 1)), 0, $result, $symbolCursor + 12, 2)
        }
        $auxiliaryCount = $result[$symbolCursor + 17]
        $symbolCursor += 18 * (1 + $auxiliaryCount)
        $symbolIndex += 1 + $auxiliaryCount
    }

    $text = [Text.Encoding]::ASCII.GetString($result)
    if ($text -match '(?i)([A-Z]:\\|\\Users\\|Windows Kits|Microsoft Visual Studio|claude-egress-proxy-eventlog-)') {
        Fail 'compatible Windows SDK tools produced nonportable resource metadata'
    }
    [System.IO.File]::WriteAllBytes($Path, $result)
}

function Get-DigestLine([string]$Path, [string]$RelativePath) {
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return "$hash  $RelativePath"
}

function New-Manifest([string]$Source, [string]$Amd64, [string]$Arm64) {
    $lines = @(
        (Get-DigestLine $Source 'assets/windows/eventlog.mc'),
        (Get-DigestLine $Amd64 'cmd/claude-egress-proxy/eventlog_windows_amd64.syso'),
        (Get-DigestLine $Arm64 'cmd/claude-egress-proxy/eventlog_windows_arm64.syso')
    ) | Sort-Object
    return [Text.Encoding]::ASCII.GetBytes((($lines -join "`n") + "`n"))
}

function Test-EqualBytes([string]$Expected, [string]$Actual) {
    if (-not (Test-Path -LiteralPath $Expected -PathType Leaf) -or -not (Test-Path -LiteralPath $Actual -PathType Leaf)) {
        return $false
    }
    $left = [System.IO.File]::ReadAllBytes($Expected)
    $right = [System.IO.File]::ReadAllBytes($Actual)
    if ($left.Length -ne $right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $left.Length; $index++) {
        if ($left[$index] -ne $right[$index]) {
            return $false
        }
    }
    return $true
}

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $source = Join-Path $repoRoot 'assets\windows\eventlog.mc'
    $manifest = Join-Path $repoRoot 'assets\windows\eventlog.sha256'
    $outputDirectory = Join-Path $repoRoot 'cmd\claude-egress-proxy'
    $amd64Output = Join-Path $outputDirectory 'eventlog_windows_amd64.syso'
    $arm64Output = Join-Path $outputDirectory 'eventlog_windows_arm64.syso'

    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        Fail 'eventlog message source is missing'
    }
    $tools = Get-SdkTools
    $cvtres = Get-CvtResTool
    if ($null -eq $tools -or [string]::IsNullOrWhiteSpace($cvtres)) {
        Fail 'compatible Windows SDK tools are unavailable'
    }

    $temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('claude-egress-proxy-eventlog-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
    try {
        $temporarySource = Join-Path $temporaryDirectory 'eventlog.mc'
        $sourceText = [System.IO.File]::ReadAllText($source, [Text.Encoding]::ASCII).Replace("`r`n", "`n").Replace("`r", "`n")
        [System.IO.File]::WriteAllText($temporarySource, $sourceText, [Text.Encoding]::ASCII)
        Push-Location -LiteralPath $temporaryDirectory
        try {
            Invoke-Tool $tools.Mc @('-U', '-h', $temporaryDirectory, '-r', $temporaryDirectory, '-z', 'eventlog', 'eventlog.mc')
            $resourceScript = Join-Path $temporaryDirectory 'eventlog.rc'
            $resource = Join-Path $temporaryDirectory 'eventlog.res'
            Invoke-Tool $tools.Rc @('/nologo', '/r', '/fo', $resource, $resourceScript)
        } finally {
            Pop-Location
        }

        $temporaryAmd64 = Join-Path $temporaryDirectory 'eventlog_windows_amd64.syso'
        $temporaryArm64 = Join-Path $temporaryDirectory 'eventlog_windows_arm64.syso'
        Invoke-Tool $cvtres @('/nologo', '/machine:X64', "/out:$temporaryAmd64", $resource)
        Invoke-Tool $cvtres @('/nologo', '/machine:ARM64', "/out:$temporaryArm64", $resource)
        Remove-CoffDebugMetadata $temporaryAmd64 0x8664
        Remove-CoffDebugMetadata $temporaryArm64 0xAA64
        $temporaryManifest = Join-Path $temporaryDirectory 'eventlog.sha256'
        [System.IO.File]::WriteAllBytes($temporaryManifest, (New-Manifest $source $temporaryAmd64 $temporaryArm64))

        if ($Verify) {
            if (-not (Test-EqualBytes $source $temporarySource) -or
                -not (Test-EqualBytes $amd64Output $temporaryAmd64) -or
                -not (Test-EqualBytes $arm64Output $temporaryArm64) -or
                -not (Test-EqualBytes $manifest $temporaryManifest)) {
                Fail 'checked-in resource artifacts differ from regenerated output'
            }
        } else {
            [System.IO.File]::Copy($temporaryAmd64, $amd64Output, $true)
            [System.IO.File]::Copy($temporaryArm64, $arm64Output, $true)
            [System.IO.File]::Copy($temporaryManifest, $manifest, $true)
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryDirectory) {
            Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
        }
    }
} catch {
    Fail 'resource generation failed'
}
