<#
.SYNOPSIS
    Installs the Elastic SIEM for ShieldPulse: Elasticsearch, Kibana, Winlogbeat (Windows event
    logs) and Filebeat (Suricata), on this machine, loopback only. Replaces Splunk, which is
    stopped and set to Manual (not uninstalled).

.DESCRIPTION
    Run from an elevated PowerShell. Every download is checked against Elastic's SHA-512.
      Elasticsearch  127.0.0.1:9200   Windows service, 1 GB heap, security on, ML off
      Kibana         127.0.0.1:5601   started by this script and from the console (not a service)
      Winlogbeat     service          Security, System, Sysmon, PowerShell, Defender logs
      Filebeat       service          Suricata eve.json (suricata module)
    You choose the 'elastic' superuser password. Kibana and the shippers get their own
    credentials: a random kibana_system password and write-only API keys, all stored in each
    component's keystore, never in config files.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\siem\elastic\install-elastic.ps1
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Version = '9.5.6',
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'Elastic'),
    [string]$DataRoot = (Join-Path $env:ProgramData 'Elastic'),
    [string]$HeapSize = '1g',
    # Re-run only the Winlogbeat/Filebeat steps against an Elasticsearch + Kibana that are
    # already installed and running (no reinstall, no password changes).
    [switch]$BeatsOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Downloads = Join-Path $env:LOCALAPPDATA 'SecurityLabs\downloads'
$Curl = "$env:SystemRoot\System32\curl.exe"
$Tar = "$env:SystemRoot\System32\tar.exe"
$Es = 'http://127.0.0.1:9200'
$Kb = 'http://127.0.0.1:5601'
$EsDir = Join-Path $InstallRoot 'elasticsearch'
$KbDir = Join-Path $InstallRoot 'kibana'
$WlbDir = Join-Path $InstallRoot 'winlogbeat'
$FbDir = Join-Path $InstallRoot 'filebeat'
$EsService = 'elasticsearch-service-x64'

$Packages = [ordered]@{
    elasticsearch = @{ Path = "elasticsearch/elasticsearch-$Version-windows-x86_64.zip"; Sha512 = 'f08af94813976ec71afb34a14b882c275cdc7e7dbc28c0c1ef1e4db31b48b071f5bd287f66f727800e56d855a88f96dd0c627c735b5ee2718be07c87e695101f'; Dir = $EsDir }
    kibana        = @{ Path = "kibana/kibana-$Version-windows-x86_64.zip"; Sha512 = '8893271d0f5b6fc09f8ce9de7671bd671c9239b5cec3989690089bba8953c6e570c920ae76ba4f655d3c937bbb62cd6776b67e9c82d8a51928856d03384694b5'; Dir = $KbDir }
    winlogbeat    = @{ Path = "beats/winlogbeat/winlogbeat-$Version-windows-x86_64.zip"; Sha512 = 'b7cf3fbac23db538abcc8c03f8af4da62eaaa56d0980fc0b408af0128cf117da1f14e3c1077cc904fa153f90e0ceacdb157c09340a76983cb60ca4b936243d75'; Dir = $WlbDir }
    filebeat      = @{ Path = "beats/filebeat/filebeat-$Version-windows-x86_64.zip"; Sha512 = 'f18bf24229cf1b614ae6f46214aa7e73a442458453ba6c9ff23369a0b85d76d42fdeb351b197835cfc7301e1b54b90c8d7ac6f95bf6e7f5bbf4352366be17817'; Dir = $FbDir }
}

# --- helpers ------------------------------------------------------------------

function Write-Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "    [OK]   $m" -ForegroundColor Green }
function Write-Info([string]$m) { Write-Host "    $m" }

function Invoke-Native([string]$Exe, [string[]]$Arguments, [string]$StdIn = $null) {
    # Native tools print to stderr; judge by exit code only (PS 5.1 would otherwise abort).
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        if ($null -ne $StdIn) { $out = $StdIn | & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } }
        else { $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } }
    } finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) { throw "$(Split-Path $Exe -Leaf) failed (exit $LASTEXITCODE):`n$(($out | Select-Object -Last 20) -join "`n")" }
    return $out
}

function New-Secret([int]$Bytes = 24) {
    # Random bytes as URL-safe base64 without padding (letters, digits, - and _ only).
    $b = New-Object byte[] $Bytes
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertTo-Plain([Security.SecureString]$s) {
    $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }
}

function Get-VerifiedPackage($pkg) {
    New-Item -ItemType Directory -Force -Path $Downloads | Out-Null
    $file = Join-Path $Downloads (Split-Path $pkg.Path -Leaf)
    $ok = (Test-Path $file) -and (Get-FileHash $file -Algorithm SHA512).Hash -eq $pkg.Sha512.ToUpper()
    if (-not $ok) {
        Write-Info "Downloading $(Split-Path $file -Leaf)"
        Invoke-Native $Curl @('-L', '--fail', '--silent', '--show-error', '--retry', '30', '--retry-delay', '5', '--retry-all-errors', '-C', '-', '-o', $file, "https://artifacts.elastic.co/downloads/$($pkg.Path)") | Out-Null
        if ((Get-FileHash $file -Algorithm SHA512).Hash -ne $pkg.Sha512.ToUpper()) { Remove-Item $file -Force; throw "SHA-512 mismatch for $(Split-Path $file -Leaf). File deleted." }
    }
    Write-Ok "SHA-512 verified: $(Split-Path $file -Leaf)"
    return $file
}

function Expand-Package([string]$Zip, [string]$Dest) {
    if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
    $tmp = "$Dest.extract"
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    Invoke-Native $Tar @('-xf', $Zip, '-C', $tmp) | Out-Null
    $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
    Move-Item $inner.FullName $Dest
    Remove-Item $tmp -Recurse -Force
}

function Invoke-Es([string]$Method, [string]$Path, $Body = $null, [string]$User = 'elastic', [string]$Password) {
    $auth = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${User}:$Password"))
    $params = @{ Method = $Method; Uri = "$Es$Path"; Headers = @{ Authorization = $auth }; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress); $params.ContentType = 'application/json' }
    Invoke-RestMethod @params
}

function Wait-Until([scriptblock]$Test, [int]$Seconds, [string]$What) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try { if (& $Test) { return } } catch { }
        Start-Sleep -Seconds 3
    }
    throw "Timed out waiting for $What"
}

function Set-YamlFile([string]$Path, [string]$Content) {
    [IO.File]::WriteAllText($Path, $Content, (New-Object Text.UTF8Encoding $false))
}

# --- 0. Inputs ----------------------------------------------------------------

Write-Step "Choose a password for the Elastic 'elastic' superuser"
while ($true) {
    $p1 = ConvertTo-Plain (Read-Host "    Password (12+ characters)" -AsSecureString)
    if ($p1.Length -lt 12) { Write-Host '    Use at least 12 characters.' -ForegroundColor Yellow; continue }
    if ($p1 -match '["\\]') { Write-Host '    Avoid double quotes and backslashes.' -ForegroundColor Yellow; continue }
    $p2 = ConvertTo-Plain (Read-Host '    Confirm' -AsSecureString)
    if ($p1 -ceq $p2) { $ElasticPassword = $p1; break }
    Write-Host '    Passwords do not match.' -ForegroundColor Yellow
}

# --- 1. Packages --------------------------------------------------------------

Write-Step "Elastic $Version packages"
$zips = @{}
foreach ($k in $Packages.Keys) { $zips[$k] = Get-VerifiedPackage $Packages[$k] }

if ($BeatsOnly) {
    Write-Step 'Existing Elasticsearch and Kibana (-BeatsOnly)'
    try { $h = Invoke-Es GET '/_cluster/health' -Password $ElasticPassword } catch { throw "Cannot use Elasticsearch at $Es with that password: $($_.Exception.Message)" }
    Write-Ok "Elasticsearch is running (health $($h.status)); password accepted"
}

if (-not $BeatsOnly) {
# --- 2. Splunk: stop and set to Manual (kept installed) -----------------------

Write-Step 'Splunk (replaced by Elastic)'
$splunk = Get-Service -Name Splunkd -ErrorAction SilentlyContinue
if ($splunk) {
    if ($splunk.Status -ne 'Stopped') { Stop-Service Splunkd -Force }
    Set-Service Splunkd -StartupType Manual
    Write-Ok 'Splunkd stopped and set to Manual. Its data and config are untouched; start it again any time.'
} else { Write-Info 'Splunk is not installed.' }

# --- 3. Elasticsearch ---------------------------------------------------------

Write-Step 'Elasticsearch'
if (Get-Service $EsService -ErrorAction SilentlyContinue) {
    Stop-Service $EsService -Force -ErrorAction SilentlyContinue
    Invoke-Native (Join-Path $EsDir 'bin\elasticsearch-service.bat') @('remove') | Out-Null
}
Expand-Package $zips.elasticsearch $EsDir
$esData = Join-Path $DataRoot 'elasticsearch\data'
$esLogs = Join-Path $DataRoot 'elasticsearch\logs'
New-Item -ItemType Directory -Force -Path $esData, $esLogs | Out-Null
Set-YamlFile (Join-Path $EsDir 'config\elasticsearch.yml') @"
# ShieldPulse single-node SIEM. Loopback only.
cluster.name: shieldpulse
node.name: shieldpulse-1
path.data: $($esData -replace '\\', '/')
path.logs: $($esLogs -replace '\\', '/')
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.enrollment.enabled: false
# HTTP TLS is off because the API listens on 127.0.0.1 only.
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
# Machine learning needs several GB of RAM; not used by this lab.
xpack.ml.enabled: false
action.destructive_requires_name: true
"@
New-Item -ItemType Directory -Force -Path (Join-Path $EsDir 'config\jvm.options.d') | Out-Null
Set-YamlFile (Join-Path $EsDir 'config\jvm.options.d\heap.options') "-Xms$HeapSize`n-Xmx$HeapSize`n"

$esKeystore = Join-Path $EsDir 'bin\elasticsearch-keystore.bat'
Invoke-Native $esKeystore @('create') | Out-Null
Invoke-Native $esKeystore @('add', '-x', '-f', 'bootstrap.password') -StdIn $ElasticPassword | Out-Null
Write-Ok 'Config written (loopback, single node, security on, 1 GB heap); bootstrap password in keystore'

Invoke-Native (Join-Path $EsDir 'bin\elasticsearch-service.bat') @('install') | Out-Null
Set-Service $EsService -StartupType Automatic
Start-Service $EsService
Write-Info 'Waiting for Elasticsearch to start (1-2 minutes)...'
Wait-Until { (Invoke-Es GET '/_cluster/health' -Password $ElasticPassword).status -in 'green', 'yellow' } 300 'Elasticsearch'
Write-Ok "Elasticsearch is running at $Es"

# Single node: no replicas, so indices are green instead of yellow.
Invoke-Es PUT '/_component_template/shieldpulse-single-node' @{ template = @{ settings = @{ number_of_replicas = 0 } } } -Password $ElasticPassword | Out-Null
Invoke-Es PUT '/_index_template/shieldpulse-no-replicas' @{ index_patterns = @('winlogbeat-*', 'filebeat-*'); priority = 1; composed_of = @('shieldpulse-single-node'); data_stream = @{} } -Password $ElasticPassword | Out-Null
} # end -not BeatsOnly (Splunk + Elasticsearch)

# --- 4. Credentials for Kibana and the shippers -------------------------------

Write-Step 'Service credentials'
if (-not $BeatsOnly) {
    $KibanaPassword = New-Secret
    Invoke-Es POST '/_security/user/kibana_system/_password' @{ password = $KibanaPassword } -Password $ElasticPassword | Out-Null
    Write-Ok 'kibana_system password set (random)'
}

function New-WriterKey([string]$Name, [string]$IndexPattern) {
    $r = Invoke-Es POST '/_security/api_key' @{
        name = $Name
        role_descriptors = @{
            $Name = @{
                cluster = @('monitor', 'read_ilm', 'read_pipeline')
                indices = @(@{ names = @($IndexPattern); privileges = @('create_doc', 'auto_configure', 'view_index_metadata') })
            }
        }
        metadata = @{ application = 'shieldpulse'; purpose = 'publish events (write-only)' }
    } -Password $ElasticPassword
    return "$($r.id):$($r.api_key)"
}
$WlbKey = New-WriterKey 'shieldpulse-winlogbeat' 'winlogbeat-*'
$FbKey = New-WriterKey 'shieldpulse-filebeat' 'filebeat-*'
Write-Ok 'Write-only API keys created for Winlogbeat and Filebeat'

# --- 5. Kibana ----------------------------------------------------------------

$KibanaReady = {
    $s = Invoke-RestMethod "$Kb/api/status" -Headers @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$ElasticPassword")) } -UseBasicParsing -TimeoutSec 15
    $s.status.overall.level -eq 'available'
}

if ($BeatsOnly) {
    Write-Step 'Kibana'
    $up = $false; try { $up = & $KibanaReady } catch { }
    if (-not $up) {
        Write-Info 'Kibana is not running; starting it (dashboards are loaded into Kibana)...'
        Start-Process -FilePath (Join-Path $KbDir 'bin\kibana.bat') -WindowStyle Hidden
        Wait-Until $KibanaReady 900 'Kibana'
    }
    Write-Ok "Kibana is running at $Kb"
} else {
Write-Step 'Kibana'
Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.ExecutablePath -like "$KbDir\*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Expand-Package $zips.kibana $KbDir
Set-YamlFile (Join-Path $KbDir 'config\kibana.yml') @"
# ShieldPulse Kibana. Loopback only.
server.host: "127.0.0.1"
server.port: 5601
server.name: "shieldpulse"
elasticsearch.hosts: ["$Es"]
elasticsearch.username: "kibana_system"
xpack.encryptedSavedObjects.encryptionKey: "$(New-Secret 36)"
xpack.security.encryptionKey: "$(New-Secret 36)"
xpack.reporting.encryptionKey: "$(New-Secret 36)"
telemetry.optIn: false
telemetry.allowChangingOptInStatus: false
"@
$kbKeystore = Join-Path $KbDir 'bin\kibana-keystore.bat'
Invoke-Native $kbKeystore @('create') | Out-Null
Invoke-Native $kbKeystore @('add', 'elasticsearch.password', '--stdin') -StdIn $KibanaPassword | Out-Null
Write-Ok 'Config written (loopback); kibana_system password in keystore'

Write-Info 'Starting Kibana (2-4 minutes on first start; longer when memory is low)...'
Start-Process -FilePath (Join-Path $KbDir 'bin\kibana.bat') -WindowStyle Hidden
Wait-Until $KibanaReady 900 'Kibana'
Write-Ok "Kibana is running at $Kb"
} # end -not BeatsOnly (Kibana)

# --- 6. Beats -----------------------------------------------------------------

function Install-Beat([string]$Name, [string]$Dir, [string]$Zip, [string]$ApiKey, [string]$Yaml, [string[]]$SetupArgs, [string]$SetupExtra = '') {
    Write-Step $Name
    if (Get-Service $Name -ErrorAction SilentlyContinue) {
        Stop-Service $Name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $Name | Out-Null
        Start-Sleep -Seconds 2
    }
    Expand-Package $Zip $Dir
    $exe = Join-Path $Dir "$Name.exe"
    Set-YamlFile (Join-Path $Dir "$Name.yml") $Yaml
    $data = Join-Path $DataRoot $Name
    New-Item -ItemType Directory -Force -Path $data | Out-Null
    $common = @('--path.home', $Dir, '--path.config', $Dir, '--path.data', $data, '--path.logs', (Join-Path $data 'logs'))

    Invoke-Native $exe ($common + @('keystore', 'create', '--force')) | Out-Null
    Invoke-Native $exe ($common + @('keystore', 'add', 'ES_API_KEY', '--stdin', '--force')) -StdIn $ApiKey | Out-Null

    # One-time setup (index templates, ingest pipelines, dashboards) needs admin rights. It runs
    # with a separate, temporary config that reads the elastic password from a temporary keystore
    # entry; both are removed afterwards. The running service only ever has the write-only key.
    $setupYml = Join-Path $Dir "$Name.setup.yml"
    Set-YamlFile $setupYml @"
output.elasticsearch:
  hosts: ["$Es"]
  username: "elastic"
  password: "`${ES_SETUP_PWD}"
setup.kibana:
  host: "$Kb"
  username: "elastic"
  password: "`${ES_SETUP_PWD}"
setup.ilm.enabled: true
$SetupExtra
"@
    Invoke-Native $exe ($common + @('keystore', 'add', 'ES_SETUP_PWD', '--stdin', '--force')) -StdIn $ElasticPassword | Out-Null
    try {
        Invoke-Native $exe ($common + @('-c', $setupYml, 'setup') + $SetupArgs) | Out-Null
    } finally {
        Invoke-Native $exe ($common + @('keystore', 'remove', 'ES_SETUP_PWD')) | Out-Null
        Remove-Item $setupYml -Force -ErrorAction SilentlyContinue
    }
    Write-Ok 'Index templates, ingest pipelines and dashboards loaded'

    $binPath = "`"$exe`" --environment=windows_service " + (($common | ForEach-Object { if ($_ -like '--*') { $_ } else { "`"$_`"" } }) -join ' ')
    New-Service -Name $Name -DisplayName "$Name (ShieldPulse)" -BinaryPathName $binPath -StartupType Automatic | Out-Null
    & sc.exe failure $Name reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    Start-Service $Name
    Write-Ok "$Name service running (restarts automatically on failure)"
}

function Get-OutputYaml([string]$Pipeline = '') {
    $pipelineLine = if ($Pipeline) { "`n  pipeline: `"$Pipeline`"" } else { '' }
    return @"
output.elasticsearch:
  hosts: ["$Es"]
  api_key: "`${ES_API_KEY}"$pipelineLine
setup.ilm.enabled: true
logging.level: info
logging.to_files: true
"@
}

# The Windows event logs prepared by siem\setup.ps1 (Sysmon, audit policy, PowerShell logging).
# Defined once and used for both the running service and the one-time 'setup' run, which
# Winlogbeat refuses to execute without an event_logs list.
$WinlogbeatEventLogs = @"
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Windows PowerShell
    event_id: 400, 403, 600, 800
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106
  - name: Microsoft-Windows-Windows Defender/Operational
"@

Install-Beat 'winlogbeat' $WlbDir $zips.winlogbeat $WlbKey (@"
# ShieldPulse: Windows event logs.
$WinlogbeatEventLogs
$(Get-OutputYaml 'winlogbeat-%{[agent.version]}-routing')
"@) @('--index-management', '--pipelines', '--dashboards') $WinlogbeatEventLogs

$eve = (Join-Path $env:ProgramFiles 'Suricata\log\eve.json') -replace '\\', '/'
Install-Beat 'filebeat' $FbDir $zips.filebeat $FbKey (@"
# ShieldPulse: Suricata IDS alerts and metadata from eve.json.
filebeat.config.modules:
  path: `${path.config}/modules.d/*.yml
  reload.enabled: false
filebeat.modules:
  - module: suricata
    eve:
      enabled: true
      var.paths: ["$eve"]
$(Get-OutputYaml)
"@) @('--index-management', '--pipelines', '--modules', 'suricata', '-M', 'suricata.eve.enabled=true')

# --- 7. Verify ----------------------------------------------------------------

Write-Step 'Checking that Windows events arrive in Elasticsearch (up to 2 minutes)'
$found = 0
$deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    try { $found = (Invoke-Es GET '/winlogbeat-*/_count?ignore_unavailable=true' -Password $ElasticPassword).count } catch { $found = 0 }
    if ($found -gt 0) { break }
    Start-Sleep -Seconds 5
}
if ($found -gt 0) { Write-Ok ("{0:N0} Windows events indexed so far (Winlogbeat reads the existing logs first, so this grows quickly)" -f $found) }
else { Write-Host '    [WARN] No events yet. Check C:\ProgramData\Elastic\winlogbeat\logs.' -ForegroundColor Yellow }

$ElasticPassword = $null; $KibanaPassword = $null; $WlbKey = $null; $FbKey = $null
Write-Host "`nElastic SIEM ready. Kibana: $Kb  (user: elastic)" -ForegroundColor Green
Write-Host 'In the ShieldPulse console, open Connections and enter the elastic login to see live data.' -ForegroundColor Green
