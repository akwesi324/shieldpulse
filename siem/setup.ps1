<#
.SYNOPSIS
    Turns this Windows machine into a well-instrumented log source for the SIEM lab.

.DESCRIPTION
    1. Installs (or updates) Sysmon with a community configuration.
    2. Enables advanced audit policy: logons, process creation with command lines,
       account and group changes, scheduled tasks, service installs.
    3. Enables PowerShell script block and module logging.
    4. Raises event log sizes so events survive until Splunk collects them.
    5. Generates harmless test activity and verifies each log source records it.

    Original settings are backed up to C:\ProgramData\SecurityLabs on the first run.
    Run with -Revert to put everything back.

.PARAMETER SysmonConfigPath
    Use your own Sysmon XML config instead of downloading the default one.

.PARAMETER SysmonConfigUrl
    Where to download the default Sysmon config from (SwiftOnSecurity sysmon-config).

.PARAMETER SkipSysmon
    Configure audit and PowerShell logging only.

.PARAMETER VerifyOnly
    Make no changes; only run the verification checks.

.PARAMETER Revert
    Uninstall Sysmon (if this script installed it) and restore the original
    audit policy, registry values and log sizes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\siem\setup.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\siem\setup.ps1 -Revert
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$SysmonConfigPath,
    [string]$SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [switch]$SkipSysmon,
    [switch]$VerifyOnly,
    [switch]$Revert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with the progress bar in PS 5.1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Paths and constants ------------------------------------------------------

$StateDir      = Join-Path $env:ProgramData 'SecurityLabs'
$StateFile     = Join-Path $StateDir 'state.json'
$AuditBackup   = Join-Path $StateDir 'auditpol-backup.csv'
$SysmonDir     = Join-Path $StateDir 'Sysmon'
$SysmonExe     = Join-Path $SysmonDir 'Sysmon64.exe'
$SysmonZipUrl  = 'https://download.sysinternals.com/files/Sysmon.zip'
$SysmonLog     = 'Microsoft-Windows-Sysmon/Operational'
$PowerShellLog = 'Microsoft-Windows-PowerShell/Operational'

# Audit subcategories to enable (success + failure).
$AuditSubcategories = @(
    'Credential Validation',       # 4776 NTLM auth
    'Logon',                       # 4624 / 4625
    'Logoff',                      # 4634 / 4647
    'Account Lockout',             # 4740
    'Special Logon',               # 4672 admin logons
    'Process Creation',            # 4688
    'User Account Management',     # 4720 user created, 4726 deleted, 4738 changed
    'Security Group Management',   # 4732 added to local group
    'Audit Policy Change',         # 4719 someone tampering with auditing
    'Other Object Access Events',  # 4698 scheduled task created
    'Security System Extension'    # 4697 service installed
)

# Registry values this script sets: path, name, value, type.
$RegistrySettings = @(
    # Make subcategory audit settings win over legacy category settings.
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Value = 1; Type = 'DWord' }
    # Include the full command line in event 4688.
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1; Type = 'DWord' }
    # PowerShell script block logging (event 4104).
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1; Type = 'DWord' }
    # PowerShell module logging (event 4103) for all modules.
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name = 'EnableModuleLogging'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name = '*'; Value = '*'; Type = 'String' }
)

# Minimum log sizes in bytes. Logs already larger are left alone.
$LogSizes = [ordered]@{
    'Security'     = 512MB
    $SysmonLog     = 256MB
    $PowerShellLog = 128MB
}

# --- Helpers ------------------------------------------------------------------

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "    [OK]   $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "    [WARN] $Message" -ForegroundColor Yellow }
function Write-Info([string]$Message) { Write-Host "    $Message" }

function Invoke-Native {
    # Runs a native command and throws if it exits non-zero (PS 5.1 does not do this itself).
    # Many tools (Sysmon included) print banners to stderr. In PS 5.1, redirecting stderr while
    # ErrorActionPreference is 'Stop' turns that text into a terminating error, so relax it here
    # and judge success by the exit code alone.
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($LASTEXITCODE -ne 0) {
        throw "'$FilePath $($Arguments -join ' ')' failed with exit code $LASTEXITCODE`n$($output | Out-String)"
    }
    return $output
}

function Get-LabState {
    if (Test-Path $StateFile) {
        $raw = Get-Content -Raw -Path $StateFile | ConvertFrom-Json
        return [pscustomobject]@{
            SysmonPreinstalled = $raw.SysmonPreinstalled
            Registry           = @($raw.Registry | ForEach-Object { $_ })
            LogSizes           = @($raw.LogSizes | ForEach-Object { $_ })
        }
    }
    return [pscustomobject]@{ SysmonPreinstalled = $null; Registry = @(); LogSizes = @() }
}

function Save-LabState($State) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    $State | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile -Encoding UTF8
}

function Get-SysmonService {
    Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
}

# --- Steps --------------------------------------------------------------------

function Install-LabSysmon($State) {
    Write-Step 'Sysmon'

    $existing = Get-SysmonService
    if ($null -eq $State.SysmonPreinstalled) {
        $State.SysmonPreinstalled = [bool]$existing
        Save-LabState $State
    }
    if ($existing -and $existing.Name -ne 'Sysmon64') {
        Write-Warn "A '$($existing.Name)' service is already installed by something else. Leaving it alone."
        return
    }

    New-Item -ItemType Directory -Force -Path $SysmonDir | Out-Null
    if (-not (Test-Path $SysmonExe)) {
        Write-Info "Downloading Sysmon from $SysmonZipUrl"
        $zip = Join-Path $SysmonDir 'Sysmon.zip'
        Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $SysmonDir -Force
        Remove-Item $zip
    }

    $sig = Get-AuthenticodeSignature -FilePath $SysmonExe
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Sysmon64.exe signature check failed (status: $($sig.Status)). Delete $SysmonDir and try again."
    }
    Write-Ok 'Sysmon64.exe is signed by Microsoft'

    if ($SysmonConfigPath) {
        $config = (Resolve-Path $SysmonConfigPath).Path
    } else {
        $config = Join-Path $SysmonDir 'sysmonconfig.xml'
        Write-Info "Downloading Sysmon config from $SysmonConfigUrl"
        Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $config -UseBasicParsing
    }
    [void][xml](Get-Content -Raw -Path $config)   # throws if the file is not valid XML
    Write-Ok "Using config $config"

    if ($existing) {
        Invoke-Native $SysmonExe @('-c', $config) | Out-Null
        Write-Ok 'Updated the running Sysmon configuration'
    } else {
        Invoke-Native $SysmonExe @('-accepteula', '-i', $config) | Out-Null
        Write-Ok 'Installed Sysmon64 service'
    }
}

function Set-LabAuditPolicy {
    Write-Step 'Advanced audit policy'

    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    if (-not (Test-Path $AuditBackup)) {
        Invoke-Native 'auditpol.exe' @('/backup', "/file:$AuditBackup") | Out-Null
        Write-Ok "Backed up the current audit policy to $AuditBackup"
    }

    foreach ($sub in $AuditSubcategories) {
        Invoke-Native 'auditpol.exe' @('/set', "/subcategory:$sub", '/success:enable', '/failure:enable') | Out-Null
        Write-Ok $sub
    }
}

function Set-LabRegistry($State) {
    Write-Step 'Registry settings (command-line auditing, PowerShell logging)'

    foreach ($s in $RegistrySettings) {
        $already = $State.Registry | Where-Object { $_.Path -eq $s.Path -and $_.Name -eq $s.Name }
        if (-not $already) {
            $prop = Get-ItemProperty -Path $s.Path -Name $s.Name -ErrorAction SilentlyContinue
            $backup = [pscustomobject]@{ Path = $s.Path; Name = $s.Name; Existed = $false; Value = $null; Type = $null }
            if ($prop) {
                $backup.Existed = $true
                $backup.Value   = $prop.($s.Name)
                $backup.Type    = (Get-Item -Path $s.Path).GetValueKind($s.Name).ToString()
            }
            $State.Registry = @($State.Registry) + $backup
            Save-LabState $State
        }

        if (-not (Test-Path $s.Path)) { New-Item -Path $s.Path -Force | Out-Null }
        New-ItemProperty -Path $s.Path -Name $s.Name -Value $s.Value -PropertyType $s.Type -Force | Out-Null
        Write-Ok "$($s.Path)\$($s.Name) = $($s.Value)"
    }
}

function Set-LabLogSizes($State) {
    Write-Step 'Event log sizes'

    foreach ($name in $LogSizes.Keys) {
        $log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
        if (-not $log) { Write-Warn "$name does not exist yet; skipped"; continue }

        if (-not ($State.LogSizes | Where-Object { $_.Name -eq $name })) {
            $State.LogSizes = @($State.LogSizes) + [pscustomobject]@{ Name = $name; MaxSize = $log.MaximumSizeInBytes }
            Save-LabState $State
        }

        $target = [long]$LogSizes[$name]
        if ($log.MaximumSizeInBytes -lt $target) {
            Invoke-Native 'wevtutil.exe' @('sl', $name, "/ms:$target") | Out-Null
            Write-Ok ('{0}: {1} MB -> {2} MB' -f $name, ($log.MaximumSizeInBytes / 1MB), ($target / 1MB))
        } else {
            Write-Ok ('{0}: already {1} MB' -f $name, ($log.MaximumSizeInBytes / 1MB))
        }
    }
}

function Test-LabLogging {
    Write-Step 'Verifying that events are recorded'

    $since  = (Get-Date).AddSeconds(-2)
    $marker = "SecurityLabs-Verify-$([guid]::NewGuid().ToString('N').Substring(0, 8))"

    # Harmless activity: run whoami and a PowerShell one-liner containing a unique marker.
    Start-Process -FilePath "$env:SystemRoot\System32\whoami.exe" -ArgumentList '/groups' -WindowStyle Hidden -Wait
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList '-NoProfile', '-Command', "Write-Output '$marker'" -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 3

    $checks = @(
        @{ Name = 'Security 4688 (process creation + command line)'; Log = 'Security'; Id = 4688; Match = 'whoami.exe' }
        @{ Name = 'Sysmon 1 (process create)';                       Log = $SysmonLog; Id = 1;  Match = 'whoami.exe' }
        @{ Name = 'PowerShell 4104 (script block)';                  Log = $PowerShellLog; Id = 4104; Match = $marker }
    )

    $failed = 0
    foreach ($c in $checks) {
        $hit = Get-WinEvent -FilterHashtable @{ LogName = $c.Log; Id = $c.Id; StartTime = $since } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -like "*$($c.Match)*" } |
            Select-Object -First 1
        if ($hit) { Write-Ok $c.Name } else { Write-Warn "$($c.Name): no matching event found"; $failed++ }
    }
    return $failed
}

function Undo-LabSetup {
    $state = Get-LabState

    Write-Step 'Reverting Sysmon'
    $svc = Get-SysmonService
    if ($state.SysmonPreinstalled -eq $false -and $svc -and $svc.Name -eq 'Sysmon64' -and (Test-Path $SysmonExe)) {
        Invoke-Native $SysmonExe @('-u', 'force') | Out-Null
        Write-Ok 'Uninstalled Sysmon64'
    } else {
        Write-Info 'Sysmon was not installed by this script; left as is.'
    }

    Write-Step 'Reverting audit policy'
    if (Test-Path $AuditBackup) {
        Invoke-Native 'auditpol.exe' @('/restore', "/file:$AuditBackup") | Out-Null
        Remove-Item $AuditBackup
        Write-Ok 'Restored the original audit policy'
    } else {
        Write-Info 'No audit policy backup found.'
    }

    Write-Step 'Reverting registry values'
    foreach ($r in $state.Registry) {
        if ($r.Existed) {
            New-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -PropertyType $r.Type -Force | Out-Null
            Write-Ok "Restored $($r.Path)\$($r.Name) = $($r.Value)"
        } elseif (Get-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $r.Path -Name $r.Name
            Write-Ok "Removed $($r.Path)\$($r.Name)"
        }
    }

    Write-Step 'Reverting log sizes'
    foreach ($l in $state.LogSizes) {
        if (Get-WinEvent -ListLog $l.Name -ErrorAction SilentlyContinue) {
            Invoke-Native 'wevtutil.exe' @('sl', $l.Name, "/ms:$($l.MaxSize)") | Out-Null
            Write-Ok ('{0}: back to {1} MB' -f $l.Name, ($l.MaxSize / 1MB))
        }
    }

    if (Test-Path $StateFile) { Remove-Item $StateFile }
    Write-Host "`nRevert complete. Sysmon binaries remain in $SysmonDir; delete that folder if you no longer need them." -ForegroundColor Cyan
}

# --- Main ---------------------------------------------------------------------

if ($Revert) {
    Undo-LabSetup
    return
}

if (-not $VerifyOnly) {
    $state = Get-LabState
    if (-not $SkipSysmon) { Install-LabSysmon $state }
    Set-LabAuditPolicy
    Set-LabRegistry $state
    Set-LabLogSizes $state
}

$failures = Test-LabLogging

if ($failures -eq 0) {
    Write-Host "`nAll log sources are working. Next step: install Splunk and add the inputs in siem\splunk\." -ForegroundColor Green
} else {
    Write-Host "`n$failures check(s) found no events. Wait a minute and re-run with -VerifyOnly; if it still fails, see siem\README.md." -ForegroundColor Yellow
    exit 1
}
