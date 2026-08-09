[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
# Policy surface (kept literal for workflow checks): go generate ./...; go mod tidy;
# git diff --exit-code -- go.mod go.sum; go vet ./...; go test ./... -count=1;
# go test -tags=resource ./integration/resource -count=1 -timeout=25m -v
function Invoke-CheckedNative([string] $File, [string[]] $Arguments) {
    $output = & $File @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "$File exited with $code" }
    return $output
}

$goFiles = @(Invoke-CheckedNative git @('ls-files', '-co', '--exclude-standard', '--', '*.go'))
if ($goFiles.Count -gt 0) {
    $gofmtArguments = @('-l') + $goFiles
    $unformatted = @(Invoke-CheckedNative gofmt $gofmtArguments)
    if ($unformatted.Count -ne 0) { throw "unformatted Go file: $($unformatted -join ', ')" }
}
Invoke-CheckedNative go @('generate', './...') | Out-Null
Invoke-CheckedNative pwsh @('-NoProfile', '-File', 'scripts/verify-generated.ps1') | Out-Null
Invoke-CheckedNative go @('mod', 'tidy') | Out-Null
Invoke-CheckedNative git @('diff', '--exit-code', '--', 'go.mod', 'go.sum') | Out-Null
Invoke-CheckedNative go @('vet', './...') | Out-Null
Invoke-CheckedNative go @('test', './...', '-count=1') | Out-Null
New-Item -ItemType Directory -Force -Path 'out/test' | Out-Null
$suffix = if ($IsWindows) { '.exe' } else { '' }
$testBinary = (Join-Path (Resolve-Path 'out/test') "claude-egress-proxy-test$suffix")
Invoke-CheckedNative go @('build', '-tags=cep_testcontrol', '-o', $testBinary, './cmd/claude-egress-proxy') | Out-Null
try {
    $env:CEP_TEST_BINARY = $testBinary
    $packages = @(Invoke-CheckedNative go @('list', './internal/...', './integration/...'))
    $racePackages = @($packages | Where-Object { $_ -notmatch '/integration/resource$' })
    Invoke-CheckedNative go (@('test', '-race') + $racePackages + @('-count=1')) | Out-Null
    Invoke-CheckedNative go @('test', '-tags=resource', './integration/resource', '-count=1', '-timeout=25m', '-v') | Out-Null
} finally {
    Remove-Item Env:CEP_TEST_BINARY -ErrorAction SilentlyContinue
}
Invoke-CheckedNative go @('test', './internal/policy', '-run=Fuzz', '-fuzz=FuzzAuthority', '-fuzztime=30s') | Out-Null
Invoke-CheckedNative go @('test', './internal/credential', '-run=Fuzz', '-fuzz=FuzzCredentialDecode', '-fuzztime=30s') | Out-Null
Invoke-CheckedNative go @('test', './internal/credential', '-run=Fuzz', '-fuzz=FuzzBasicVerifier', '-fuzztime=30s') | Out-Null
Invoke-CheckedNative go @('test', './internal/wire', '-run=Fuzz', '-fuzz=FuzzFramingValues', '-fuzztime=30s') | Out-Null
Invoke-CheckedNative pwsh @('-NoProfile', '-File', 'scripts/verify-public-data.ps1') | Out-Null
Invoke-CheckedNative pwsh @('-NoProfile', '-File', 'scripts/verify-secrets.ps1') | Out-Null
Invoke-CheckedNative pwsh @('-NoProfile', '-File', 'scripts/verify-release.ps1') | Out-Null
Invoke-CheckedNative go @('run', 'golang.org/x/vuln/cmd/govulncheck@v1.6.0', './...') | Out-Null
Invoke-CheckedNative git @('diff', '--check') | Out-Null
$status = @(Invoke-CheckedNative git @('status', '--short'))
if ($status.Count -ne 0) { throw 'verification leaves a dirty working tree' }
Write-Output 'CEP_LOCAL_VERIFICATION_OK'
