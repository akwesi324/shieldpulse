<#
.SYNOPSIS
    Checks that the Elastic SIEM is receiving and parsing this machine's logs. No Administrator.

.DESCRIPTION
    1. Elasticsearch answers on 127.0.0.1:9200 and the credentials work (version, cluster health).
    2. Events are arriving from each log source in the last 24 hours (Security, System, Sysmon,
       PowerShell; Defender and Suricata are optional).
    3. Fields are parsed into ECS: a Sysmon event has process.command_line, a Security event has
       event.code.
    4. Kibana is reachable on 127.0.0.1:5601.
    Exit code 0 when every required check passes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\siem\elastic\verify-elastic.ps1
#>
[CmdletBinding()]
param([pscredential]$Credential, [string]$Url = 'http://127.0.0.1:9200', [string]$KibanaUrl = 'http://127.0.0.1:5601')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "    [OK]   $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "    [WARN] $m" -ForegroundColor Yellow }
function Write-Info([string]$m) { Write-Host "    $m" }

if (-not $Credential) { $Credential = Get-Credential -UserName 'elastic' -Message 'Elastic credentials' }
if (-not $Credential) { throw 'No credentials entered.' }
$pair = '{0}:{1}' -f $Credential.UserName, $Credential.GetNetworkCredential().Password
$headers = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair)) }
$pair = $null

function Invoke-Es([string]$Method, [string]$Path, $Body = $null) {
    $p = @{ Method = $Method; Uri = "$Url$Path"; Headers = $headers; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 20 -Compress); $p.ContentType = 'application/json' }
    Invoke-RestMethod @p
}

$failures = 0

Write-Step 'Elasticsearch'
try {
    $info = Invoke-Es GET '/'
    $health = Invoke-Es GET '/_cluster/health'
    Write-Ok "Elasticsearch $($info.version.number), cluster '$($info.cluster_name)', health $($health.status)"
} catch {
    $code = $null
    if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    if ($code -eq 401) { throw 'Login failed: wrong username or password.' }
    throw "Cannot reach $Url. Is the elasticsearch-service-x64 service running? ($($_.Exception.Message))"
}

Write-Step 'Events per log source (last 24 hours)'
$sources = [ordered]@{
    'Windows Security' = @{ q = @{ term = @{ 'winlog.channel' = 'Security' } }; required = $true }
    'Windows System'   = @{ q = @{ term = @{ 'winlog.channel' = 'System' } }; required = $true }
    'Sysmon'           = @{ q = @{ term = @{ 'winlog.channel' = 'Microsoft-Windows-Sysmon/Operational' } }; required = $true }
    'PowerShell'       = @{ q = @{ terms = @{ 'winlog.channel' = @('Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell') } }; required = $true }
    'Defender'         = @{ q = @{ term = @{ 'winlog.channel' = 'Microsoft-Windows-Windows Defender/Operational' } }; required = $false }
    'Suricata IDS'     = @{ q = @{ term = @{ 'event.module' = 'suricata' } }; required = $false }
}
$filters = @{}
foreach ($k in $sources.Keys) { $filters[$k] = $sources[$k].q }
$r = Invoke-Es POST '/winlogbeat-*,filebeat-*/_search?ignore_unavailable=true&allow_no_indices=true' @{
    size = 0; query = @{ range = @{ '@timestamp' = @{ gte = 'now-24h' } } }
    aggs = @{ s = @{ filters = @{ filters = $filters } } }
}
foreach ($k in $sources.Keys) {
    $n = $r.aggregations.s.buckets.$k.doc_count
    if ($n -gt 0) { Write-Ok ('{0,-17} {1,10:N0} events' -f $k, $n) }
    elseif ($sources[$k].required) { Write-Warn ('{0,-17} no events in the last 24 hours' -f $k); $failures++ }
    else { Write-Info ('{0,-17} none yet (normal until it is running / has activity)' -f $k) }
}

Write-Step 'ECS field parsing'
$checks = @(
    @{ Name = 'Sysmon process.command_line'; Query = @{ bool = @{ filter = @(@{ term = @{ 'winlog.channel' = 'Microsoft-Windows-Sysmon/Operational' } }, @{ term = @{ 'event.code' = '1' } }, @{ exists = @{ field = 'process.command_line' } }) } }; Field = 'process' }
    @{ Name = 'Security event.code';         Query = @{ bool = @{ filter = @(@{ term = @{ 'winlog.channel' = 'Security' } }, @{ exists = @{ field = 'event.code' } }) } }; Field = 'event' }
)
foreach ($c in $checks) {
    $hit = Invoke-Es POST '/winlogbeat-*/_search?ignore_unavailable=true&allow_no_indices=true' @{ size = 1; query = $c.Query; sort = @(@{ '@timestamp' = 'desc' }) }
    if ($hit.hits.total.value -gt 0) {
        $doc = $hit.hits.hits[0]._source
        $sample = if ($c.Field -eq 'process') { $doc.process.command_line } else { $doc.event.code }
        $text = "$sample"; if ($text.Length -gt 70) { $text = $text.Substring(0, 70) + '...' }
        Write-Ok "$($c.Name)  (e.g. $text)"
    } else { Write-Warn "$($c.Name): not found"; $failures++ }
}

Write-Step 'Kibana'
try {
    Invoke-RestMethod "$KibanaUrl/api/status" -Headers $headers -UseBasicParsing -TimeoutSec 10 | Out-Null
    Write-Ok "Kibana is up: $KibanaUrl"
} catch { Write-Info "Kibana is not running (start it from the console when you need it)." }

if ($failures -eq 0) { Write-Host "`nElastic is receiving and parsing all lab logs." -ForegroundColor Green; exit 0 }
Write-Host "`n$failures check(s) failed. Winlogbeat logs: C:\ProgramData\Elastic\winlogbeat\logs" -ForegroundColor Yellow
exit 1
