<#
.SYNOPSIS
    Post-install tuning for the single-node Elastic SIEM. No Administrator needed.

.DESCRIPTION
    1. Replicas: a single node cannot host replica shards, which leaves the cluster "yellow".
       Sets number_of_replicas = 0 on the Winlogbeat/Filebeat index templates (so future backing
       indices are created without replicas) and on the existing backing indices.
    2. Noise report: lists which parent processes produce the "Encoded PowerShell command"
       watchlist hits, so known automation can be excluded without hiding real activity.
    Writes a report to %LOCALAPPDATA%\SecurityLabs\elastic-tune-report.json.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\siem\elastic\tune-elastic.ps1
#>
[CmdletBinding()]
param([pscredential]$Credential, [string]$Url = 'http://127.0.0.1:9200')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Write-Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "    [OK]   $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "    [WARN] $m" -ForegroundColor Yellow }

if (-not $Credential) { $Credential = Get-Credential -UserName 'elastic' -Message 'Elastic superuser password (the one you chose during install)' }
if (-not $Credential) { throw 'No credentials entered.' }
$pair = '{0}:{1}' -f $Credential.UserName, $Credential.GetNetworkCredential().Password
$headers = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair)) }
$pair = $null

function Invoke-Es([string]$Method, [string]$Path, $Body = $null) {
    $p = @{ Method = $Method; Uri = "$Url$Path"; Headers = $headers; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 30 -Compress); $p.ContentType = 'application/json' }
    Invoke-RestMethod @p
}

$report = [ordered]@{ ranAt = (Get-Date).ToString('s') }

Write-Step 'Cluster health before'
$before = Invoke-Es GET '/_cluster/health'
Write-Host "    status $($before.status), unassigned shards $($before.unassigned_shards)"
$report.healthBefore = $before.status

Write-Step 'Index templates: number_of_replicas = 0'
# The _index_template API takes one name or wildcard per request (no comma lists).
$templates = @()
foreach ($pattern in 'winlogbeat*', 'filebeat*') {
    try { $templates += @((Invoke-Es GET "/_index_template/$pattern").index_templates) } catch { }
}
foreach ($t in $templates) {
    $def = $t.index_template
    if (-not $def.PSObject.Properties['template']) { $def | Add-Member template ([pscustomobject]@{}) }
    if (-not $def.template.PSObject.Properties['settings']) { $def.template | Add-Member settings ([pscustomobject]@{}) }
    if (-not $def.template.settings.PSObject.Properties['index']) { $def.template.settings | Add-Member index ([pscustomobject]@{}) }
    $def.template.settings.index | Add-Member number_of_replicas '0' -Force
    # Elasticsearch 9 returns system-managed fields that may not be sent back on PUT.
    foreach ($sys in 'created_date', 'created_date_millis', 'modified_date', 'modified_date_millis') {
        if ($def.PSObject.Properties[$sys]) { $def.PSObject.Properties.Remove($sys) }
    }
    Invoke-Es PUT "/_index_template/$($t.name)" $def | Out-Null
    Write-Ok $t.name
}
if (-not $templates) { Write-Warn 'No Winlogbeat/Filebeat index templates found.' }
# Our own earlier attempt (lower priority, never applied): remove to avoid confusion.
try { Invoke-Es DELETE '/_index_template/shieldpulse-no-replicas' | Out-Null; Invoke-Es DELETE '/_component_template/shieldpulse-single-node' | Out-Null } catch { }

Write-Step 'Existing indices: number_of_replicas = 0'
Invoke-Es PUT '/winlogbeat-*,filebeat-*,.ds-winlogbeat-*,.ds-filebeat-*/_settings?expand_wildcards=all&allow_no_indices=true' @{ index = @{ number_of_replicas = 0 } } | Out-Null
Write-Ok 'Updated'

Start-Sleep -Seconds 5
$after = Invoke-Es GET '/_cluster/health'
$report.healthAfter = $after.status
if ($after.status -eq 'green') { Write-Ok 'Cluster health: green' }
else {
    Write-Warn "Cluster health still $($after.status); unassigned shards:"
    $un = Invoke-Es GET '/_cat/shards?format=json&h=index,shard,prirep,state'
    $report.unassigned = @($un | Where-Object { $_.state -eq 'UNASSIGNED' } | ForEach-Object { "$($_.index) [$($_.prirep)]" })
    $report.unassigned | ForEach-Object { Write-Host "      $_" }
}

Write-Step 'Encoded PowerShell watch: what produces the hits (last 24 h)'
$w = (Get-Content -Raw (Join-Path $PSScriptRoot '..\..\console\watches.json') | ConvertFrom-Json).watches | Where-Object id -eq 'encoded-powershell'
$q = @{ bool = @{ filter = @($w.query, @{ range = @{ '@timestamp' = @{ gte = 'now-24h' } } }) } }
$r = Invoke-Es POST '/winlogbeat-*/_search?ignore_unavailable=true' @{
    size = 0; query = $q
    aggs = @{ parents = @{ terms = @{ field = 'process.parent.executable'; size = 15; missing = '(none)' }
                          aggs = @{ images = @{ terms = @{ field = 'process.executable'; size = 3 } } } } }
}
$report.encodedPowerShellTotal = $r.hits.total.value
$report.encodedPowerShellParents = @($r.aggregations.parents.buckets | ForEach-Object {
    [ordered]@{ parent = $_.key; count = $_.doc_count; images = @($_.images.buckets | ForEach-Object { "$($_.key) ($($_.doc_count))" }) }
})
$report.encodedPowerShellParents | ForEach-Object { Write-Host ("    {0,6}  {1}" -f $_.count, $_.parent) }

$out = Join-Path $env:LOCALAPPDATA 'SecurityLabs\elastic-tune-report.json'
[IO.File]::WriteAllText($out, ($report | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding $false))
Write-Host "`nReport written to $out" -ForegroundColor Green
