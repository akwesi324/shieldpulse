<#
.SYNOPSIS
    Starts the Security Labs Console (http://127.0.0.1:7700) and opens it in the browser.
    If it is already running, just opens the browser.
#>
[CmdletBinding()]
param([int]$Port = 7700)

$ErrorActionPreference = 'Stop'
$url = "http://127.0.0.1:$Port"

function Test-Console {
    try { Invoke-WebRequest "$url/api/state" -UseBasicParsing -TimeoutSec 3 | Out-Null; return $true } catch { return $false }
}

if (-not (Test-Console)) {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js is not on PATH.' }
    $env:LAB_CONSOLE_PORT = "$Port"
    Start-Process -FilePath 'node' -ArgumentList "`"$(Join-Path $PSScriptRoot 'server.js')`"" -WindowStyle Minimized
    $deadline = (Get-Date).AddSeconds(15)
    while (-not (Test-Console)) {
        if ((Get-Date) -gt $deadline) { throw "Console did not start on $url" }
        Start-Sleep -Milliseconds 500
    }
}
Write-Host "Security Labs Console: $url" -ForegroundColor Green
Start-Process $url
