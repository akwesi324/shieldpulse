<#
.SYNOPSIS
    Installs the minimal Android build toolchain for the Security Labs mobile app.
    No Android Studio, no Gradle, no Administrator.

.DESCRIPTION
    Into %LOCALAPPDATA%\SecurityLabs\android\:
      jdk\   Eclipse Temurin JDK 21 (SHA-256 checked against Adoptium's published value)
      sdk\   Android command-line tools (SHA-1 checked against Google's repository index), then via
             sdkmanager (which verifies its own downloads): platforms;android-35, build-tools;35.0.0

    Running this script accepts the Android SDK license agreements on your behalf.
    Safe to re-run; finished steps are skipped.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Root      = Join-Path $env:LOCALAPPDATA 'SecurityLabs\android'
$JdkDir    = Join-Path $Root 'jdk'
$SdkDir    = Join-Path $Root 'sdk'
$Downloads = Join-Path $Root 'downloads'
$Curl      = "$env:SystemRoot\System32\curl.exe"
$Tar       = "$env:SystemRoot\System32\tar.exe"

$Jdk = @{
    Url    = 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.zip'
    Sha256 = 'a4dbaa05fca4bd89d84584e58c459bd732efebb1722af80ab13c6516832004f9'
}
$CmdlineTools = @{
    Url  = 'https://dl.google.com/android/repository/commandlinetools-win-16111833_latest.zip'
    Sha1 = '57d04f2d75eb8e8fffc5000a987e5de4b5a63e9d'
}
$SdkPackages = @('platforms;android-35', 'build-tools;35.0.0')

function Invoke-Native([scriptblock]$Command) {
    # Java and sdkmanager write normal output to stderr; in PS 5.1 that is an error under 'Stop'.
    # Run with 'Continue' and judge success by the exit code instead.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $previous }
}

function Write-Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "    [OK]   $m" -ForegroundColor Green }

function Get-Verified([string]$Url, [string]$Algorithm, [string]$Expected) {
    New-Item -ItemType Directory -Force -Path $Downloads | Out-Null
    $file = Join-Path $Downloads ([Uri]::UnescapeDataString(($Url -split '/')[-1]))
    if (-not ((Test-Path $file) -and (Get-FileHash $file -Algorithm $Algorithm).Hash -eq $Expected.ToUpper())) {
        Write-Host "    Downloading $(Split-Path $file -Leaf)"
        $out = Invoke-Native { & $Curl -L --fail --silent --show-error --retry 20 --retry-delay 5 --retry-all-errors -o $file $Url }
        if ($LASTEXITCODE -ne 0) { throw "Download failed: $Url`n$($out -join "`n")" }
        $actual = (Get-FileHash $file -Algorithm $Algorithm).Hash
        if ($actual -ne $Expected.ToUpper()) { Remove-Item $file -Force; throw "$Algorithm mismatch for $(Split-Path $file -Leaf). File deleted." }
    }
    Write-Ok "$Algorithm verified: $(Split-Path $file -Leaf)"
    return $file
}

# --- JDK ----------------------------------------------------------------------
Write-Step 'Eclipse Temurin JDK 21'
$java = Join-Path $JdkDir 'bin\java.exe'
if (-not (Test-Path $java)) {
    $zip = Get-Verified $Jdk.Url 'SHA256' $Jdk.Sha256
    if (Test-Path $JdkDir) { Remove-Item $JdkDir -Recurse -Force }
    $tmp = Join-Path $Root 'jdk-extract'
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    & $Tar -xf $zip -C $tmp
    if ($LASTEXITCODE -ne 0) { throw 'JDK extraction failed' }
    Move-Item (Get-ChildItem $tmp -Directory | Select-Object -First 1).FullName $JdkDir
    Remove-Item $tmp -Recurse -Force
}
Write-Ok ((Invoke-Native { & $java -version }) | Select-Object -First 1)

# --- Command-line tools -------------------------------------------------------
Write-Step 'Android command-line tools'
$sdkmanager = Join-Path $SdkDir 'cmdline-tools\latest\bin\sdkmanager.bat'
if (-not (Test-Path $sdkmanager)) {
    $zip = Get-Verified $CmdlineTools.Url 'SHA1' $CmdlineTools.Sha1
    $tmp = Join-Path $Root 'clt-extract'
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    & $Tar -xf $zip -C $tmp
    if ($LASTEXITCODE -ne 0) { throw 'Command-line tools extraction failed' }
    # sdkmanager requires the layout <sdk>\cmdline-tools\latest\bin
    New-Item -ItemType Directory -Force -Path (Join-Path $SdkDir 'cmdline-tools') | Out-Null
    Move-Item (Join-Path $tmp 'cmdline-tools') (Join-Path $SdkDir 'cmdline-tools\latest')
    Remove-Item $tmp -Recurse -Force
}
Write-Ok 'sdkmanager ready'

# --- SDK packages -------------------------------------------------------------
Write-Step "SDK packages: $($SdkPackages -join ', ')"
$env:JAVA_HOME = $JdkDir
$env:ANDROID_HOME = $SdkDir
$missing = @($SdkPackages | Where-Object { -not (Test-Path (Join-Path $SdkDir ($_ -replace ';', '\'))) })
if ($missing.Count) {
    # sdkmanager is a .bat file: cmd.exe splits arguments at ';', so each package name must be
    # wrapped in literal double quotes. Licenses are accepted by answering 'y' to its prompts
    # (the user approved this); current versions ask during install instead of via --licenses.
    $quoted = @($missing | ForEach-Object { '"' + $_ + '"' })
    $yes = @('y') * 30
    Write-Host '    Downloading SDK packages (several hundred MB)...'
    $out = Invoke-Native { $yes | & $sdkmanager --sdk_root="$SdkDir" @quoted }
    if ($LASTEXITCODE -ne 0) { throw "sdkmanager failed with exit code $LASTEXITCODE`n$(($out | Select-Object -Last 10) -join "`n")" }
}
foreach ($p in $SdkPackages) {
    if (-not (Test-Path (Join-Path $SdkDir ($p -replace ';', '\')))) { throw "$p is missing after install" }
    Write-Ok $p
}

Write-Host "`nToolchain ready in $Root" -ForegroundColor Green
