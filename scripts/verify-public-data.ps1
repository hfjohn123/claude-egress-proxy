[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$forbidden = @(
    '(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*["''][A-Za-z0-9_\-/+=]{16,}["'']',
    '(?i)(?<!\$env:)anthropic[_-]?api[_-]?key',
    '(?i)C:\\Users\\',
    '(?i)https?://(?!(?:[^/]+\.)?example(?:\.|(?::\d+)?(?:/|$))|proxy(?:/|:)|localhost|127\.0\.0\.1|\[::1\]|spdx\.dev|github\.com|ghcr\.io|docker\.io|apache\.org|www\.apache\.org|code\.claude\.com|golang\.org)[^/]+')
$files = git ls-files
if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed' }
foreach ($pattern in $forbidden) {
    $matches = Select-String -Path $files -Pattern $pattern -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -notmatch '(_test\.go|\.ps1)$' }
    if ($matches) { throw "public-data policy match: $($matches[0].Path):$($matches[0].LineNumber)" }
}
