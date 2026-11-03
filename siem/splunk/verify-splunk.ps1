<#
.SYNOPSIS
    Checks that Splunk is receiving and parsing this machine's logs.

.DESCRIPTION
    Uses Splunk's REST API (management port 8089), so it never waits on an interactive
    prompt and every request has a timeout. Does not need Administrator.

    Checks:
      1. Splunk's management API answers and the credentials work.
      2. Events are arriving in wineventlog, sysmon and powershell (defender is optional).
      3. The add-ons extract fields: Sysmon CommandLine, Windows EventCode.

    Exit code 0 when every required check passes, 1 otherwise.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\siem\splunk\verify-splunk.ps1
#>
[CmdletBinding()]
param(
    [pscredential]$Credential,
    [string]$ManagementUrl = 'https://localhost:8089',
    [int]$TimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "    [OK]   $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "    [WARN] $Message" -ForegroundColor Yellow }
function Write-Info([string]$Message) { Write-Host "    $Message" }

if (-not $Credential) {
    $Credential = Get-Credential -UserName 'admin' -Message 'Splunk admin credentials'
    if (-not $Credential) { throw 'No credentials entered.' }
}

# Splunk's management port uses a self-signed certificate by default. Accept it only for
# loopback addresses; any other host must present a certificate Windows trusts.
# This must be compiled C#, not a PowerShell script block: Splunk renegotiates TLS, .NET then
# calls the callback on a background thread with no PowerShell runspace, and a script-block
# callback fails there with "The underlying connection was closed".
if (-not ('LocalSplunkCert' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class LocalSplunkCert {
    public static void Install() {
        ServicePointManager.ServerCertificateValidationCallback = Validate;
    }
    static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        if (errors == SslPolicyErrors.None) return true;
        HttpWebRequest req = sender as HttpWebRequest;
        return req != null && req.RequestUri.IsLoopback;
    }
}
'@
}
[LocalSplunkCert]::Install()

$pair    = '{0}:{1}' -f $Credential.UserName, $Credential.GetNetworkCredential().Password
$headers = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair)) }
$pair    = $null

function Invoke-SplunkSearch([string]$Query) {
    # Runs a search to completion and returns the results as objects.
    $body = @{ search = "search $Query"; output_mode = 'csv'; exec_mode = 'oneshot' }
    $csv = Invoke-RestMethod -Method Post -Uri "$ManagementUrl/services/search/jobs/export" `
        -Headers $headers -Body $body -TimeoutSec 60
    if ([string]::IsNullOrWhiteSpace($csv)) { return @() }
    return @($csv | ConvertFrom-Csv)
}

$failures = 0

# --- 1. API and credentials ---------------------------------------------------
Write-Step 'Connecting to the Splunk management API'
try {
    $info = Invoke-RestMethod -Uri "$ManagementUrl/services/server/info?output_mode=json" -Headers $headers -TimeoutSec 30
    $content = $info.entry[0].content
    Write-Ok "Splunk $($content.version) on $($content.serverName), license: $($content.activeLicenseGroup)"
} catch {
    $status = $null
    if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
    if ($status -eq 401) { throw 'Login failed: wrong username or password.' }
    throw "Could not reach $ManagementUrl. Is the Splunkd service running? ($($_.Exception.Message))"
}

# --- 2. Events per index ------------------------------------------------------
Write-Step "Checking that events are arriving (up to $TimeoutSeconds s)"
$required = 'wineventlog', 'sysmon', 'powershell'
$optional = 'defender'
$counts   = @{}
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
do {
    $rows = Invoke-SplunkSearch 'index IN (wineventlog, sysmon, powershell, defender) earliest=-24h | stats count by index'
    foreach ($r in $rows) { $counts[$r.index] = [int]$r.count }
    $missing = @($required | Where-Object { -not $counts.ContainsKey($_) })
    if ($missing.Count -eq 0) { break }
    Start-Sleep -Seconds 10
} while ((Get-Date) -lt $deadline)

foreach ($idx in $required) {
    if ($counts.ContainsKey($idx)) { Write-Ok ('{0,-12} {1,8:N0} events' -f $idx, $counts[$idx]) }
    else { Write-Warn ('{0,-12} no events in the last 24 hours' -f $idx); $failures++ }
}
if ($counts.ContainsKey($optional)) { Write-Ok ('{0,-12} {1,8:N0} events' -f $optional, $counts[$optional]) }
else { Write-Info ('{0,-12} no events yet (normal until Defender logs something)' -f $optional) }

# --- 3. Field extraction from the add-ons -------------------------------------
Write-Step 'Checking field extraction (add-ons)'
$fieldChecks = @(
    @{ Name = 'Sysmon add-on: CommandLine on Sysmon event 1'; Query = 'index=sysmon EventCode=1 CommandLine=* earliest=-24h | head 1 | table CommandLine'; Field = 'CommandLine' }
    @{ Name = 'Windows add-on: EventCode on Security events'; Query = 'index=wineventlog source="XmlWinEventLog:Security" EventCode=* earliest=-24h | head 1 | table EventCode'; Field = 'EventCode' }
)
foreach ($c in $fieldChecks) {
    $row = Invoke-SplunkSearch $c.Query | Select-Object -First 1
    if ($row -and $row.($c.Field)) {
        $sample = "$($row.($c.Field))"
        if ($sample.Length -gt 60) { $sample = $sample.Substring(0, 60) + '...' }
        Write-Ok "$($c.Name)  (e.g. $sample)"
    } else {
        Write-Warn "$($c.Name): field not extracted. Is the add-on installed?"
        $failures++
    }
}

# --- Result -------------------------------------------------------------------
if ($failures -eq 0) {
    Write-Host "`nSplunk is receiving and parsing all lab logs. Open http://localhost:8000" -ForegroundColor Green
    exit 0
}
Write-Host "`n$failures check(s) failed. See siem\README.md (Troubleshooting)." -ForegroundColor Yellow
exit 1
