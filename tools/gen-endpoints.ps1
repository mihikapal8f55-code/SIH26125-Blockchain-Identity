# Regenerate static/js/endpoints.js from the Flask routes in app.py.
#
#   powershell -ExecutionPolicy Bypass -File tools\gen-endpoints.ps1
#
# Only routes whose method set is exactly GET are emitted: the command
# palette calls them straight from the browser, so every mutating route
# must stay behind its own UI button.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Get-Content (Join-Path $root 'app.py') -Raw

$pattern = [regex]"@app\.route\(\s*'([^']+)'([^)]*)\)"
$rows = New-Object System.Collections.Generic.List[string]

foreach ($m in $pattern.Matches($src)) {
    $path = $m.Groups[1].Value
    $rest = $m.Groups[2].Value

    $methods = 'GET'
    if ($rest -match "methods\s*=\s*\[([^\]]*)\]") {
        $methods = (($Matches[1] -split ',') |
            ForEach-Object { $_.Trim().Trim("'", '"', ' ') } |
            Where-Object { $_ }) -join '+'
    }
    if ($methods -ne 'GET') { continue }

    $rows.Add("    { path: '$path', methods: 'GET' }")
}

$header = @"
/* ==================================================================
 * SIH26125 - endpoint catalogue for the command palette.
 *
 * GENERATED FILE - do not edit by hand.
 * Source: app.py   Generator: tools/gen-endpoints.ps1
 *
 * Only routes whose method set is exactly GET are listed: the palette
 * calls them directly from the browser, so anything that mutates chain
 * state must stay behind its own UI button.
 * ================================================================== */
window.PALETTE_ENDPOINTS = [
"@

$out = $header + ($rows -join ",`n") + "`n];`n"
[System.IO.File]::WriteAllText((Join-Path $root 'static\js\endpoints.js'), $out)

Write-Host "Wrote static/js/endpoints.js with $($rows.Count) GET routes."
