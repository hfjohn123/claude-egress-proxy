[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$forbidden = @(
    '(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*["'']?[A-Za-z0-9_\-/+=]{16,}',
    '(?i)anthropic[_-]?api[_-]?key',
    '(?i)C:\\Users\\',
    '(?i)https?://(?!example\.|localhost|127\.0\.0\.1|\[::1\])[^/]+')
$files = git ls-files
if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed' }
foreach ($pattern in $forbidden) {
    $matches = Select-String -Path $files -Pattern $pattern -ErrorAction SilentlyContinue
    if ($matches) { throw "public-data policy match: $($matches[0].Path):$($matches[0].LineNumber)" }
}
