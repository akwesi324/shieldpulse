<#
.SYNOPSIS
    Installs Splunk Enterprise on this machine and configures it for the SIEM lab.

.DESCRIPTION
    1. Finds the Splunk Enterprise MSI (-MsiPath, or the newest splunk-*.msi in Downloads), or
       downloads the pinned release and checks it against Splunk's published SHA-512.
       Either way, checks that the MSI is signed by Splunk.
    2. Installs Splunk silently, running as Local System so it can read the Security log.
       You are prompted for the admin password; it is never written to disk by this script.
    3. Copies the security_labs app (indexes + event log inputs) into Splunk.
    4. Installs any add-ons (.tgz / .spl) found in siem\splunk\addons\.
    5. Restarts Splunk and checks that events are arriving in each index.

    Safe to re-run: if Splunk is already installed, steps 1-2 are skipped.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\siem\splunk\install-splunk.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\siem\splunk\install-splunk.ps1 -MsiPath D:\splunk-10.x.msi
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$MsiPath,
    # Pinned Splunk Enterprise release, downloaded when no MSI is found locally.
    [string]$MsiUrl = 'https://download.splunk.com/products/splunk/releases/10.6.1.1/windows/splunk-10.6.1.1-b2ae2962645c-windows-x64.msi',
    [string]$AddonDir = (Join-Path $PSScriptRoot 'addons'),
    [string]$AdminUser = 'admin',
    [string]$SplunkHome = (Join-Path $env:ProgramFiles 'Splunk')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppSource = Join-Path $PSScriptRoot 'security_labs'
$SplunkExe = Join-Path $SplunkHome 'bin\splunk.exe'
$LogDir    = Join-Path $env:ProgramData 'SecurityLabs'
$InstallerDir = Join-Path $LogDir 'installers'

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "    [OK]   $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "    [WARN] $Message" -ForegroundColor Yellow }
function Write-Info([string]$Message) { Write-Host "    $Message" }

function Invoke-Native {
    # Runs a native command; fails only on a non-zero exit code (stderr text is not an error).
    param([string]$FilePath, [string[]]$Arguments, [switch]$AllowFailure)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        # Never echo the arguments: they can contain -auth credentials.
        throw "'$(Split-Path $FilePath -Leaf)' failed with exit code $LASTEXITCODE`n$($output | Out-String)"
    }
    return $output
}

function ConvertTo-PlainText([Security.SecureString]$Secure) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Read-AdminPassword([switch]$New) {
    while ($true) {
        $first = ConvertTo-PlainText (Read-Host "    Splunk password for '$AdminUser'" -AsSecureString)
        if (-not $New) { return $first }
        if ($first.Length -lt 8)  { Write-Warn 'Use at least 8 characters.'; continue }
        if ($first -match '["\s]') { Write-Warn 'Avoid spaces and double quotes (they break the silent installer).'; continue }
        $second = ConvertTo-PlainText (Read-Host '    Confirm password' -AsSecureString)
        if ($first -ceq $second) { return $first }
        Write-Warn 'Passwords do not match.'
    }
}

function Find-SplunkMsi {
    if ($MsiPath) { return (Resolve-Path $MsiPath).Path }

    # Use an MSI already in Downloads or the lab's installer cache if there is one.
    $searchDirs = (Join-Path $env:USERPROFILE 'Downloads'), $InstallerDir
    $msi = Get-ChildItem -Path $searchDirs -Filter 'splunk-*.msi' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch 'forwarder' } |
        # Skips partial or corrupted downloads, which have no valid signature.
        Where-Object { (Get-AuthenticodeSignature -FilePath $_.FullName).Status -eq 'Valid' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($msi) { return $msi.FullName }

    # Otherwise download the pinned version and verify it against Splunk's published SHA-512.
    New-Item -ItemType Directory -Force -Path $InstallerDir | Out-Null
    $target = Join-Path $InstallerDir (Split-Path $MsiUrl -Leaf)
    Write-Info "Downloading $(Split-Path $MsiUrl -Leaf) (about 1.1 GB)..."
    # Retry dropped connections and resume a partial download instead of starting over.
    Invoke-Native "$env:SystemRoot\System32\curl.exe" @('-L', '--fail', '--silent', '--show-error',
        '--retry', '10', '--retry-delay', '5', '--retry-all-errors', '-C', '-', '-o', $target, $MsiUrl) | Out-Null

    $published = (Invoke-Native "$env:SystemRoot\System32\curl.exe" @('-L', '--fail', '--silent', "$MsiUrl.sha512")) -join ''
    if ($published -notmatch '([0-9a-fA-F]{128})') { throw "Could not read the published checksum from $MsiUrl.sha512" }
    $actual = (Get-FileHash -Path $target -Algorithm SHA512).Hash
    if ($actual -ne $Matches[1].ToUpper()) {
        Remove-Item $target
        throw 'Downloaded MSI does not match the SHA-512 published by Splunk. Deleted it; try again.'
    }
    Write-Ok 'SHA-512 matches the checksum published by Splunk'
    return $target
}

function Install-Splunk([string]$Password) {
    Write-Step 'Installing Splunk Enterprise'

    $msi = Find-SplunkMsi
    $sig = Get-AuthenticodeSignature -FilePath $msi
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Splunk') {
        throw "Installer signature check failed for $msi (status: $($sig.Status))."
    }
    Write-Ok "Installer $(Split-Path $msi -Leaf) is signed by Splunk"

    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $log = Join-Path $LogDir 'splunk-install.log'
    # /Le logs errors only, so the password property is not written to the log.
    $msiArgs = @(
        '/i', "`"$msi`"",
        'AGREETOLICENSE=Yes',
        "SPLUNKUSERNAME=$AdminUser",
        "SPLUNKPASSWORD=`"$Password`"",
        'USE_LOCAL_SYSTEM=1',
        'LAUNCHSPLUNK=0',
        '/quiet', '/norestart',
        '/Le', "`"$log`""
    )
    Write-Info 'Running the installer (this takes a few minutes)...'
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -notin 0, 3010) {
        throw "msiexec failed with exit code $($proc.ExitCode). See $log"
    }
    Write-Ok "Installed to $SplunkHome"
}

function Install-LabApp {
    Write-Step 'Installing the security_labs app (indexes + inputs)'
    $dest = Join-Path $SplunkHome 'etc\apps\security_labs'
    # Replace the deployed app entirely so files removed or moved in the repo do not linger.
    if (Test-Path $dest) { Remove-Item -Path $dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item -Path (Join-Path $AppSource '*') -Destination $dest -Recurse -Force
    Write-Ok "Copied to $dest"
}

function Install-Addons {
    Write-Step 'Installing add-ons'
    $packages = @(Get-ChildItem -Path $AddonDir -Include '*.tgz', '*.spl', '*.tar.gz' -Recurse -ErrorAction SilentlyContinue)
    if ($packages.Count -eq 0) {
        Write-Warn "No add-ons in $AddonDir. Download them from Splunkbase (see siem\README.md) and re-run."
        return
    }
    foreach ($p in $packages) {
        Invoke-Native $SplunkExe @('install', 'app', $p.FullName, '-update', '1') | Out-Null
        Write-Ok $p.Name
    }
}

# --- Main ---------------------------------------------------------------------

$freshInstall = -not (Test-Path $SplunkExe)
if ($freshInstall) {
    Write-Step "Choose a password for the Splunk '$AdminUser' account"
    $password = Read-AdminPassword -New
    Install-Splunk $password
} else {
    Write-Step "Splunk is already installed at $SplunkHome"
    $password = Read-AdminPassword
}

Install-LabApp

Write-Step 'Starting Splunk'
Invoke-Native $SplunkExe @('start', '--accept-license', '--answer-yes', '--no-prompt') | Out-Null
Write-Ok 'splunkd is running'

# Log in once; later CLI commands reuse the session, so the password is not repeated on command lines.
Invoke-Native $SplunkExe @('login', '-auth', "${AdminUser}:$password") | Out-Null

Install-Addons

Write-Step 'Restarting Splunk to load the app and add-ons'
Invoke-Native $SplunkExe @('restart') | Out-Null
Write-Ok 'Restarted'

# Verify over the REST API (verify-splunk.ps1) rather than 'splunk search': the CLI session
# is invalidated by the restart, and the CLI would then wait on a hidden login prompt.
$secure = ConvertTo-SecureString $password -AsPlainText -Force
$password = $null
$credential = New-Object System.Management.Automation.PSCredential($AdminUser, $secure)
& (Join-Path $PSScriptRoot 'verify-splunk.ps1') -Credential $credential

Write-Host "`nSplunk Web: http://localhost:8000  (user: $AdminUser)" -ForegroundColor Green
Write-Host 'Try: index=sysmon EventCode=1 | table _time Image CommandLine ParentImage' -ForegroundColor Green
