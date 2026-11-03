<#
.SYNOPSIS
    Builds the Security Labs Android app (android\app) into a signed APK, using the Android SDK
    tools directly: aapt2 -> javac -> d8 -> zipalign -> apksigner. No Gradle.

.DESCRIPTION
    Requires the toolchain from setup-toolchain.ps1.
    Signing key: created on the first build at %LOCALAPPDATA%\SecurityLabs\android\signing\
    (outside the repo); its password is stored DPAPI-encrypted for your Windows account. Keep
    this key: Android only installs updates signed with the same key.

    Output: android\dist\SecurityLabs-<version>.apk

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\android\build-apk.ps1
#>
[CmdletBinding()]
param(
    [string]$VersionName = '1.0.0',
    [int]$VersionCode = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root       = Join-Path $env:LOCALAPPDATA 'SecurityLabs\android'
$Jdk        = Join-Path $Root 'jdk'
$Sdk        = Join-Path $Root 'sdk'
$BuildTools = Join-Path $Sdk 'build-tools\35.0.0'
$AndroidJar = Join-Path $Sdk 'platforms\android-35\android.jar'
$SigningDir = Join-Path $Root 'signing'
$Keystore   = Join-Path $SigningDir 'securitylabs.jks'
$KsPassFile = Join-Path $SigningDir 'keystore-password.dpapi'

$App   = Join-Path $PSScriptRoot 'app'
$Build = Join-Path $PSScriptRoot 'build'
$Dist  = Join-Path $PSScriptRoot 'dist'
$MinSdk = 26
$TargetSdk = 35

function Write-Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "    [OK]   $m" -ForegroundColor Green }

function Invoke-Tool([string]$Exe, [string[]]$Arguments) {
    # Native tools print to stderr; judge success by exit code (PS 5.1 would otherwise abort).
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "$(Split-Path $Exe -Leaf) failed (exit $LASTEXITCODE):`n$(($out | Select-Object -Last 25) -join "`n")" }
    return $out
}

foreach ($p in @($Jdk, $BuildTools, $AndroidJar)) {
    if (-not (Test-Path $p)) { throw "Missing $p. Run android\setup-toolchain.ps1 first." }
}
$env:JAVA_HOME = $Jdk
$env:Path = "$Jdk\bin;$env:Path"
$aapt2     = Join-Path $BuildTools 'aapt2.exe'
$d8        = Join-Path $BuildTools 'd8.bat'
$zipalign  = Join-Path $BuildTools 'zipalign.exe'
$apksigner = Join-Path $BuildTools 'apksigner.bat'

# Keep the in-app version label in sync with the APK.
$verFile = Join-Path $App 'java\com\maskedops\securitylabs\BuildConfigInfo.java'
$verSrc = [IO.File]::ReadAllText($verFile)
$verNew = [regex]::Replace($verSrc, 'VERSION = "[^"]*"', "VERSION = `"$VersionName`"")
if ($verNew -ne $verSrc) { [IO.File]::WriteAllText($verFile, $verNew, (New-Object Text.UTF8Encoding $false)) }

if (Test-Path $Build) { Remove-Item $Build -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Build, $Dist, "$Build\gen", "$Build\classes", "$Build\dex" | Out-Null

# --- 1. Resources -------------------------------------------------------------
Write-Step 'Compiling resources (aapt2)'
Invoke-Tool $aapt2 @('compile', '--dir', (Join-Path $App 'res'), '-o', "$Build\res.zip") | Out-Null
Invoke-Tool $aapt2 @('link', '-I', $AndroidJar, '--manifest', (Join-Path $App 'AndroidManifest.xml'),
    '-A', (Join-Path $App 'assets'), '-R', "$Build\res.zip", '--java', "$Build\gen", '--auto-add-overlay',
    '--min-sdk-version', "$MinSdk", '--target-sdk-version', "$TargetSdk",
    '--version-code', "$VersionCode", '--version-name', $VersionName,
    '-o', "$Build\app-res.apk") | Out-Null
Write-Ok 'Resources, manifest and assets linked'

# --- 2. Java -> DEX -----------------------------------------------------------
Write-Step 'Compiling Java (javac) and dexing (d8)'
$sources = @(Get-ChildItem (Join-Path $App 'java'), "$Build\gen" -Recurse -Filter '*.java' | ForEach-Object { $_.FullName })
Invoke-Tool (Join-Path $Jdk 'bin\javac.exe') (@('--release', '11', '-encoding', 'UTF-8', '-nowarn', '-Xlint:-options',
    '-classpath', $AndroidJar, '-d', "$Build\classes") + $sources) | Out-Null
$classes = @(Get-ChildItem "$Build\classes" -Recurse -Filter '*.class' | ForEach-Object { $_.FullName })
Invoke-Tool $d8 (@('--release', '--min-api', "$MinSdk", '--lib', $AndroidJar, '--output', "$Build\dex") + $classes) | Out-Null
Write-Ok "$($sources.Count) source files -> classes.dex"

# --- 3. Package ---------------------------------------------------------------
Write-Step 'Packaging'
$unaligned = "$Build\app-unaligned.apk"
Copy-Item "$Build\app-res.apk" $unaligned
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::Open($unaligned, [IO.Compression.ZipArchiveMode]::Update)
try { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, "$Build\dex\classes.dex", 'classes.dex', [IO.Compression.CompressionLevel]::Optimal) }
finally { $zip.Dispose() }
$aligned = "$Build\app-aligned.apk"
Invoke-Tool $zipalign @('-f', '-p', '4', $unaligned, $aligned) | Out-Null
Write-Ok 'zipalign'

# --- 4. Sign ------------------------------------------------------------------
Write-Step 'Signing (apksigner)'
New-Item -ItemType Directory -Force -Path $SigningDir | Out-Null
if (-not (Test-Path $Keystore)) {
    $pw = [Convert]::ToBase64String((New-Object Security.Cryptography.RNGCryptoServiceProvider | ForEach-Object { $b = New-Object byte[] 24; $_.GetBytes($b); $b }))
    ConvertTo-SecureString $pw -AsPlainText -Force | ConvertFrom-SecureString | Set-Content -Path $KsPassFile -Encoding ASCII
    $env:SL_KS_PASS = $pw
    Invoke-Tool (Join-Path $Jdk 'bin\keytool.exe') @('-genkeypair', '-keystore', $Keystore, '-storetype', 'PKCS12',
        '-alias', 'securitylabs', '-keyalg', 'RSA', '-keysize', '3072', '-validity', '10000',
        '-dname', 'CN=MaskedOps Security Labs, O=MaskedOps', '-storepass:env', 'SL_KS_PASS') | Out-Null
    Write-Ok "Created signing key $Keystore (back it up: updates must be signed with it)"
} else {
    $secure = Get-Content $KsPassFile | ConvertTo-SecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $env:SL_KS_PASS = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
$apk = Join-Path $Dist "SecurityLabs-$VersionName.apk"
try {
    Invoke-Tool $apksigner @('sign', '--ks', $Keystore, '--ks-key-alias', 'securitylabs', '--ks-pass', 'env:SL_KS_PASS',
        '--min-sdk-version', "$MinSdk", '--out', $apk, $aligned) | Out-Null
} finally { Remove-Item Env:\SL_KS_PASS -ErrorAction SilentlyContinue }
$verify = Invoke-Tool $apksigner @('verify', '--verbose', '--print-certs', $apk)
Write-Ok (($verify | Where-Object { $_ -match 'Verified using v2 scheme|Signer #1 certificate SHA-256' }) -join '; ')

# --- 5. Report ----------------------------------------------------------------
$badging = Invoke-Tool $aapt2 @('dump', 'badging', $apk)
$pkg = ($badging | Where-Object { $_ -match '^package:' }) -replace "\s*platformBuildVersion.*", ''
Write-Host "`n$pkg" -ForegroundColor Green
Write-Host ("APK: {0}  ({1:N0} KB, SHA-256 {2})" -f $apk, ((Get-Item $apk).Length / 1KB), (Get-FileHash $apk -Algorithm SHA256).Hash.ToLower()) -ForegroundColor Green
