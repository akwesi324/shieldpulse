<#
.SYNOPSIS
    Keeps the Security Labs Console running in the background, always available at
    http://127.0.0.1:7700.

.DESCRIPTION
    Registers a per-user scheduled task (no Administrator needed) that:
      - starts the console hidden (no window) when you sign in to Windows;
      - re-checks every minute and starts it again if it has stopped or crashed
        (if it is already running, the check does nothing);
      - has no time limit and keeps running on battery.
    The console runs in your interactive session, so the tool windows it launches appear normally.
    Logs: %LOCALAPPDATA%\SecurityLabs\console\console.log

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\console\autostart.ps1            # install and start now
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\console\autostart.ps1 -Status
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\console\autostart.ps1 -Remove    # uninstall and stop
#>
[CmdletBinding()]
param([switch]$Remove, [switch]$Status)

$ErrorActionPreference = 'Stop'
$TaskName = 'Security Labs Console'
$TaskPath = '\SecurityLabs\'
$Url      = 'http://127.0.0.1:7700'
$Server   = Join-Path $PSScriptRoot 'server.js'
$LogFile  = Join-Path $env:LOCALAPPDATA 'SecurityLabs\console\console.log'
$User     = "$env:USERDOMAIN\$env:USERNAME"

function Test-Console {
    try { Invoke-WebRequest "$Url/api/state" -UseBasicParsing -TimeoutSec 5 | Out-Null; return $true } catch { return $false }
}

function Stop-ConsoleProcesses {
    Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine -like '*console*server.js*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Get-LabTask { Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue }

if ($Status) {
    $task = Get-LabTask
    if (-not $task) { Write-Host 'Autostart: not installed' -ForegroundColor Yellow }
    else {
        $info = $task | Get-ScheduledTaskInfo
        Write-Host "Autostart: installed (task state: $($task.State); last run $($info.LastRunTime), result $($info.LastTaskResult))" -ForegroundColor Green
    }
    if (Test-Console) { Write-Host "Console: running at $Url" -ForegroundColor Green } else { Write-Host 'Console: not responding' -ForegroundColor Yellow }
    Write-Host "Log: $LogFile"
    return
}

if ($Remove) {
    if (Get-LabTask) {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Host 'Removed the autostart task.' -ForegroundColor Green
    } else { Write-Host 'Autostart task was not installed.' }
    Stop-ConsoleProcesses
    Write-Host 'Stopped the background console.'
    return
}

# --- Install ------------------------------------------------------------------
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { throw 'Node.js is not on PATH.' }

# conhost --headless runs the console with no window at all.
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" `
    -Argument "--headless `"$node`" `"$Server`"" -WorkingDirectory $PSScriptRoot

# Trigger 1: at sign-in, so the console is up right away.
# Trigger 2: watchdog - a schedule repeating every minute, indefinitely, from now on (it keeps its
# schedule across reboots). A repetition attached to the sign-in trigger would only start counting
# after the next sign-in, so it is a separate trigger. MultipleInstances=IgnoreNew makes each tick a
# no-op while the console runs, and starts it again if it has exited.
$atLogOn  = New-ScheduledTaskTrigger -AtLogOn -User $User
$watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30) -RepetitionInterval (New-TimeSpan -Minutes 1)
$trigger  = @($atLogOn, $watchdog)

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -Priority 7 `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

$principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited

# Replace any manually started console so the task owns the port.
Stop-ConsoleProcesses
Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Description "Runs the Security Labs Console at $Url in the background." -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath

$deadline = (Get-Date).AddSeconds(30)
while (-not (Test-Console)) {
    if ((Get-Date) -gt $deadline) { throw "The task started but the console is not answering on $Url. See $LogFile" }
    Start-Sleep -Milliseconds 500
}
Write-Host "Autostart installed. The console is running in the background at $Url" -ForegroundColor Green
Write-Host 'It starts automatically when you sign in, and restarts within a minute if it stops.'
Write-Host "Logs: $LogFile    Remove: .\console\autostart.ps1 -Remove"
