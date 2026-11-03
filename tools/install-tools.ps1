<#
.SYNOPSIS
    Downloads, verifies and installs the lab tools listed in tools\manifest.json.

.DESCRIPTION
    Two modes:
      (default)  Portable and per-user tools. No Administrator needed. Installs to
                 %LOCALAPPDATA%\SecurityLabs\tools\<id>.
      -Admin     Tools that need Administrator: Npcap (interactive installer), Wireshark,
                 Suricata + Emerging Threats Open rules, and the Splunk input for Suricata.

    Every download is checked before use: the SHA-256 pinned in the manifest, the Authenticode
    signer for vendors that do not publish hashes (Sysinternals, Npcap), or winget's own hash
    check. A failed check deletes the file and stops that tool's install.

    Installed paths are recorded in tools\installed.json under the tools folder so that the
    Security Labs Console can show status and launch each tool.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\tools\install-tools.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\tools\install-tools.ps1 -Admin     # from an elevated prompt

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\tools\install-tools.ps1 -Only hayabusa,yara -Force
#>
[CmdletBinding()]
param(
    [switch]$Admin,
    [string[]]$Only,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoRoot      = Split-Path $PSScriptRoot -Parent
$Manifest      = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'manifest.json')) | ConvertFrom-Json
$LabRoot       = Join-Path $env:LOCALAPPDATA 'SecurityLabs'
$ToolsRoot     = Join-Path $LabRoot 'tools'
$DownloadDir   = Join-Path $LabRoot 'downloads'
$InstalledFile = Join-Path $ToolsRoot 'installed.json'
$Curl          = "$env:SystemRoot\System32\curl.exe"
$Tar           = "$env:SystemRoot\System32\tar.exe"
$ProgramFiles  = $env:ProgramFiles

# --- Output helpers -----------------------------------------------------------

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)   { Write-Host "    [OK]   $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "    [WARN] $Message" -ForegroundColor Yellow }
function Write-Info([string]$Message) { Write-Host "    $Message" }

function Invoke-Native {
    # Runs a native command; fails only on a non-zero exit code (stderr text is not an error).
    param([string]$FilePath, [string[]]$Arguments, [int[]]$OkCodes = @(0))
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($OkCodes -notcontains $LASTEXITCODE) {
        throw "'$(Split-Path $FilePath -Leaf)' failed with exit code $LASTEXITCODE`n$(($output | Select-Object -Last 15) -join "`n")"
    }
    return $output
}

function Test-IsAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- installed.json -----------------------------------------------------------

function Read-Installed {
    $table = @{}
    if (Test-Path $InstalledFile) {
        $obj = [IO.File]::ReadAllText($InstalledFile) | ConvertFrom-Json
        foreach ($p in $obj.PSObject.Properties) { $table[$p.Name] = $p.Value }
    }
    return $table
}

function Save-InstalledEntry([string]$Id, [string]$Entry, [string]$Version) {
    # Named mutex: user-mode and -Admin runs can execute at the same time; without the lock,
    # one could overwrite the other's read-modify-write of installed.json.
    $mutex = New-Object Threading.Mutex($false, 'Local\SecurityLabsInstalledJson')
    [void]$mutex.WaitOne(30000)
    try {
        $table = Read-Installed
        $table[$Id] = [ordered]@{ entry = $Entry; version = $Version; installedAt = (Get-Date).ToString('s') }
        New-Item -ItemType Directory -Force -Path $ToolsRoot | Out-Null
        # UTF-8 without BOM so Node's JSON.parse can read it.
        [IO.File]::WriteAllText($InstalledFile, ($table | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
    } finally {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}

function Get-InstalledEntry([string]$Id) {
    $table = Read-Installed
    if ($table.ContainsKey($Id) -and $table[$Id].entry -and (Test-Path $table[$Id].entry)) { return $table[$Id].entry }
    return $null
}

# --- Download and verification ------------------------------------------------

function Get-VerifiedDownload([string]$Url, [string]$Sha256) {
    New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null
    $name = [Uri]::UnescapeDataString(($Url -split '/')[-1])
    if ($name -notmatch '\.') { $name += '.zip' }   # codeload archive URLs end in a commit hash
    $file = Join-Path $DownloadDir $name

    if ($Sha256 -and (Test-Path $file) -and ((Get-FileHash $file -Algorithm SHA256).Hash -eq $Sha256.ToUpper())) {
        Write-Info "Using cached $name"
        return $file
    }

    Write-Info "Downloading $name"
    Invoke-Native $Curl @('-L', '--fail', '--silent', '--show-error', '--retry', '10', '--retry-delay', '5',
        '--retry-all-errors', '-o', $file, $Url) | Out-Null

    if ($Sha256) {
        $actual = (Get-FileHash $file -Algorithm SHA256).Hash
        if ($actual -ne $Sha256.ToUpper()) {
            Remove-Item $file -Force
            throw "SHA-256 mismatch for $name (expected $Sha256, got $actual). File deleted."
        }
        Write-Ok 'SHA-256 matches the pinned value'
    }
    return $file
}

function Assert-Signed([string]$Path, [string]$Signer) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch [regex]::Escape($Signer)) {
        throw "Signature check failed for $(Split-Path $Path -Leaf): status $($sig.Status), signer '$($sig.SignerCertificate.Subject)'"
    }
}

function Expand-Download([string]$File, [string]$Destination) {
    if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null

    if ($File -match '\.exe\.gz$') {
        # A single gzip-compressed executable.
        $out = Join-Path $Destination ([IO.Path]::GetFileNameWithoutExtension($File))
        $in = [IO.File]::OpenRead($File)
        try {
            $gz = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
            $fs = [IO.File]::Create($out)
            try { $gz.CopyTo($fs) } finally { $fs.Dispose(); $gz.Dispose() }
        } finally { $in.Dispose() }
        return
    }

    # Windows' bsdtar extracts .zip and .tar.gz quickly.
    Invoke-Native $Tar @('-xf', $File, '-C', $Destination) | Out-Null

    # Flatten a single top-level folder so paths are predictable ({DIR}\node.exe, not {DIR}\node-v24...\node.exe).
    $top = @(Get-ChildItem -Path $Destination -Force)
    if ($top.Count -eq 1 -and $top[0].PSIsContainer) {
        $inner = $top[0].FullName
        Get-ChildItem -Path $inner -Force | Move-Item -Destination $Destination
        Remove-Item $inner -Recurse -Force
    }
}

function Resolve-Entry([string]$Dir, [string]$Pattern) {
    $hit = Get-ChildItem -Path $Dir -Filter $Pattern -Recurse -Force -ErrorAction SilentlyContinue |
        Sort-Object { $_.FullName.Length } | Select-Object -First 1
    if (-not $hit) { throw "Installed, but '$Pattern' was not found under $Dir" }
    return $hit.FullName
}

# --- Installers by type -------------------------------------------------------

function Install-Archive($Tool) {
    $i = $Tool.install
    $dir = Join-Path $ToolsRoot $Tool.id
    $sha = $null; if ($i.PSObject.Properties['sha256']) { $sha = $i.sha256 }
    $file = Get-VerifiedDownload $i.url $sha
    Expand-Download $file $dir

    if ($i.PSObject.Properties['authenticode']) {
        foreach ($name in $i.authenticode) { Assert-Signed (Join-Path $dir $name) $i.signer }
        Write-Ok "Signed by $($i.signer): $($i.authenticode -join ', ')"
    }
    if (-not $sha -and -not $i.PSObject.Properties['authenticode']) { Write-Warn 'No published checksum or signature to verify against.' }

    return (Resolve-Entry $dir $i.entry)
}

function Install-Venv($Tool) {
    $dir = Join-Path $ToolsRoot $Tool.id
    $py = Join-Path $dir 'Scripts\python.exe'
    if (-not (Test-Path $py)) {
        Invoke-Native 'python' @('-m', 'venv', $dir) | Out-Null
        Invoke-Native $py @('-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', '--upgrade', 'pip') | Out-Null
    }
    Write-Ok "Virtual environment at $dir"
    return $py
}

function Install-Pip($Tool) {
    $py = Join-Path (Join-Path $ToolsRoot $Tool.install.venv) 'Scripts\python.exe'
    if (-not (Test-Path $py)) { throw "Python environment '$($Tool.install.venv)' is missing; install it first." }
    Write-Info "pip install $($Tool.install.packages -join ' ')"
    Invoke-Native $py (@('-m', 'pip', 'install', '--quiet', '--disable-pip-version-check') + @($Tool.install.packages)) | Out-Null
    $versions = Invoke-Native $py @('-m', 'pip', 'list', '--format=freeze', '--disable-pip-version-check')
    $names = @($Tool.install.packages | ForEach-Object { $_.ToLower() })
    $pinned = $versions | Where-Object { $names -contains (($_ -split '==')[0].ToLower()) }
    Write-Ok ($pinned -join ', ')
    if ($Tool.install.PSObject.Properties['entry']) { return (Join-Path (Split-Path (Split-Path $py)) $Tool.install.entry) }
    return $Tool.detect.path.Replace('{TOOLS}', $ToolsRoot)
}

function Install-Npm($Tool) {
    $node = Get-InstalledEntry $Tool.install.node
    if (-not $node) { throw "Node runtime '$($Tool.install.node)' is missing; install it first." }
    $nodeDir = Split-Path $node
    $npmCli = Join-Path $nodeDir 'node_modules\npm\bin\npm-cli.js'
    $dir = Join-Path $ToolsRoot $Tool.id
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    # Put the private Node first on PATH so install scripts run under Node 24, not the system Node.
    $oldPath = $env:Path
    $env:Path = "$nodeDir;$env:Path"
    try {
        Write-Info "npm install $($Tool.install.package) (several minutes; n8n is large)"
        Invoke-Native $node @($npmCli, 'install', $Tool.install.package, '--prefix', $dir,
            '--no-audit', '--no-fund', '--loglevel=error') | Out-Null
    } finally { $env:Path = $oldPath }

    $entry = Join-Path $dir 'node_modules\n8n\bin\n8n'
    if (-not (Test-Path $entry)) { throw "npm finished but $entry is missing." }
    return $entry
}

function Install-PsModule($Tool) {
    $i = $Tool.install
    $dir = Join-Path $ToolsRoot $Tool.id
    if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue |
              Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
    }
    if (-not (Get-Module -ListAvailable -Name $i.module | Where-Object { $_.Version -eq [version]$i.version })) {
        Write-Info "Install-Module $($i.module) $($i.version) (PowerShell Gallery)"
        Install-Module -Name $i.module -RequiredVersion $i.version -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    }
    Import-Module $i.module -RequiredVersion $i.version -Force
    Write-Ok "$($i.module) $($i.version)"

    if ($i.atomics) {
        # Sparse, blob-less clone of only the test definitions (atomics/T*/T*.yaml). Payload
        # binaries in the repo are never downloaded: smaller, and nothing for Defender to flag.
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git is required to fetch the atomic test definitions.' }
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
        Write-Info 'Fetching atomic test definitions only (sparse git checkout, no payloads)'
        Invoke-Native 'git' @('clone', '--quiet', '--depth', '1', '--filter=blob:none', '--no-checkout',
            'https://github.com/redcanaryco/atomic-red-team.git', $dir) | Out-Null
        Invoke-Native 'git' @('-C', $dir, 'sparse-checkout', 'set', '--no-cone', '/atomics/T*/T*.yaml') | Out-Null
        Invoke-Native 'git' @('-C', $dir, 'checkout', '--quiet') | Out-Null
        $commit = (Invoke-Native 'git' @('-C', $dir, 'rev-parse', '--short', 'HEAD')) -join ''
        $count = @(Get-ChildItem -Path (Join-Path $dir 'atomics') -Filter 'T*.yaml' -Recurse).Count
        Write-Ok "$count technique definitions from atomic-red-team@$commit in $dir\atomics"
    }
    return (Join-Path $dir 'atomics')
}

function Install-Interactive($Tool) {
    $i = $Tool.install
    $file = Get-VerifiedDownload $i.url $null
    Assert-Signed $file $i.signer
    Write-Ok "Installer is signed by $($i.signer)"
    Write-Host "    >>> The $($Tool.name) installer is opening. Click through it with the default options." -ForegroundColor Magenta
    $p = Start-Process -FilePath $file -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "$($Tool.name) installer exited with code $($p.ExitCode) (cancelled?)." }
    if (-not (Get-Service -Name $Tool.detect.service -ErrorAction SilentlyContinue)) { throw "$($Tool.name) service '$($Tool.detect.service)' not found after install." }
    return "service:$($Tool.detect.service)"
}

function Install-Winget($Tool) {
    $i = $Tool.install
    Write-Info "winget install $($i.package) $($i.version) (winget verifies the installer hash)"
    # -1978335189 = already installed / no applicable upgrade.
    Invoke-Native 'winget' @('install', '--id', $i.package, '--exact', '--version', $i.version, '--silent',
        '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity') -OkCodes @(0, -1978335189) | Out-Null
    $entry = $Tool.detect.path.Replace('{PF}', $ProgramFiles)
    if (-not (Test-Path $entry)) { throw "winget finished but $entry is missing." }
    if ($Tool.id -eq 'suricata') { Install-SuricataRules $Tool (Split-Path $entry) }
    return $entry
}

# --- Suricata post-install ----------------------------------------------------

function Install-SuricataRules($Tool, [string]$SuricataDir) {
    $url = $Tool.install.rulesUrl
    $file = Get-VerifiedDownload $url $null
    $md5Published = ((Invoke-Native $Curl @('-sL', '--fail', "$url.md5")) -join '').Trim().ToUpper()
    $md5Actual = (Get-FileHash $file -Algorithm MD5).Hash
    if ($md5Published -notmatch '^[0-9A-F]{32}$' -or $md5Actual -ne $md5Published) {
        Remove-Item $file -Force
        throw 'Emerging Threats rules failed the published MD5 check. File deleted.'
    }
    Write-Ok 'ET Open rules match the published checksum'

    $tmp = Join-Path $DownloadDir 'et-rules'
    Expand-Download $file $tmp

    $yamlPath = Join-Path $SuricataDir 'suricata.yaml'
    $yaml = [IO.File]::ReadAllText($yamlPath)
    $ruleDir = Join-Path $SuricataDir 'rules'
    if ($yaml -match '(?m)^default-rule-path:\s*"?([^"\r\n]+?)"?\s*$') {
        $candidate = $Matches[1].Trim() -replace '\\\\', '\'   # YAML escapes backslashes: C:\\Program Files\\...
        if (-not [IO.Path]::IsPathRooted($candidate)) { $candidate = Join-Path $SuricataDir $candidate }
        $ruleDir = $candidate.TrimEnd('\')
    }
    New-Item -ItemType Directory -Force -Path $ruleDir | Out-Null

    # The Windows suricata.yaml lists the individual ET files (emerging-*.rules, botcc.rules, ...)
    # under rule-files, so install them under their own names.
    $rules = @(Get-ChildItem -Path $tmp -Filter '*.rules' -Recurse)
    $count = 0
    foreach ($r in $rules) {
        Copy-Item -Path $r.FullName -Destination (Join-Path $ruleDir $r.Name) -Force
        $count += @([IO.File]::ReadLines($r.FullName) | Where-Object { $_ -match '^\s*alert ' }).Count
    }
    Remove-Item $tmp -Recurse -Force
    $stale = Join-Path $ruleDir 'suricata.rules'   # combined file from an earlier version of this script
    if (Test-Path $stale) { Remove-Item $stale -Force }
    Write-Ok ("{0} rule files ({1:N0} enabled rules) installed to {2}" -f $rules.Count, $count, $ruleDir)

    # The default suricata.yaml can list files the current ET Open set no longer ships; Suricata
    # treats a missing rule file as an error, so create empty placeholders for those.
    $listed = @([regex]::Matches($yaml, '(?m)^\s*-\s*([\w.-]+\.rules)\s*$') | ForEach-Object { $_.Groups[1].Value })
    $missing = @($listed | Where-Object { -not (Test-Path (Join-Path $ruleDir $_)) })
    foreach ($m in $missing) {
        [IO.File]::WriteAllText((Join-Path $ruleDir $m), "# Placeholder: listed in suricata.yaml but not part of the current ET Open set.`n")
    }
    if ($missing.Count) { Write-Ok ("Created empty placeholders for {0} rule file(s) ET no longer ships: {1}" -f $missing.Count, ($missing -join ', ')) }

    if (-not (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll")) {
        throw 'Npcap is not installed (wpcap.dll missing), so Suricata cannot start. Install Npcap first, then re-run.'
    }

    Test-SuricataRules $SuricataDir $yamlPath $ruleDir
    Update-SplunkForSuricata
}

function Test-SuricataRules([string]$SuricataDir, [string]$YamlPath, [string]$RuleDir) {
    # Runs 'suricata -T'. Rules this build cannot parse (e.g. 'file.magic' needs libmagic, which the
    # Windows build lacks) are commented out with a reason - not deleted - and the test is repeated.
    $exe = Join-Path $SuricataDir 'suricata.exe'
    $disabled = 0
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        Write-Info "Testing the Suricata configuration (pass $attempt, about a minute)..."
        $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $out = @(& $exe -T -c $YamlPath 2>&1 | ForEach-Object { "$_" }) } finally { $ErrorActionPreference = $previous }
        if ($LASTEXITCODE -eq 0) {
            if ($disabled) { Write-Ok "Disabled $disabled rule(s) this Suricata build cannot parse" }
            Write-Ok 'suricata -T: configuration and rules load cleanly'
            return
        }

        $badSids = @($out | Where-Object { $_ -match 'error parsing signature' } |
            ForEach-Object { if ($_ -match 'sid:\s*(\d+)\s*;') { $Matches[1] } } | Sort-Object -Unique)
        $reasons = @($out | Where-Object { $_ -match "unknown rule keyword '([^']+)'" } | ForEach-Object { $Matches[1] } | Sort-Object -Unique)
        if (-not $badSids.Count) {
            throw "suricata -T failed:`n$(($out | Where-Object { $_ -match '^E:' } | Select-Object -First 10) -join "`n")"
        }

        $reason = if ($reasons.Count) { "unsupported keyword(s): $($reasons -join ', ')" } else { 'failed to parse on this build' }
        $sidPattern = 'sid:\s*(' + ($badSids -join '|') + ')\s*;'
        foreach ($file in Get-ChildItem -Path $RuleDir -Filter '*.rules') {
            $lines = [IO.File]::ReadAllLines($file.FullName)
            $changed = $false
            for ($n = 0; $n -lt $lines.Length; $n++) {
                if ($lines[$n] -match '^\s*(alert|drop|pass|reject) ' -and $lines[$n] -match $sidPattern) {
                    $lines[$n] = "# [security-labs] disabled, $reason`: " + $lines[$n]
                    $changed = $true; $disabled++
                }
            }
            if ($changed) { [IO.File]::WriteAllLines($file.FullName, $lines) }
        }
        Write-Info ("Disabled {0} rule(s): {1}" -f $badSids.Count, $reason)
    }
    throw 'suricata -T still fails after 5 passes; see the Suricata output above.'
}

function Update-SplunkForSuricata {
    $splunkApp = Join-Path $ProgramFiles 'Splunk\etc\apps\security_labs'
    if (-not (Test-Path $splunkApp)) { Write-Warn 'Splunk lab app not found; skipping the Suricata input.'; return }
    $source = Join-Path $RepoRoot 'siem\splunk\security_labs'
    Remove-Item $splunkApp -Recurse -Force
    Copy-Item -Path $source -Destination $splunkApp -Recurse -Force
    Restart-Service -Name Splunkd
    Write-Ok "Splunk now collects eve.json into the 'suricata' index (app redeployed, Splunkd restarted)"
}

# --- Main ---------------------------------------------------------------------

if ($Admin -and -not (Test-IsAdmin)) { throw 'Run -Admin from an elevated PowerShell (Run as Administrator).' }
New-Item -ItemType Directory -Force -Path $ToolsRoot | Out-Null

$results = New-Object System.Collections.Generic.List[object]
foreach ($tool in $Manifest.tools) {
    $i = $tool.install
    $needsAdmin = [bool]($i.PSObject.Properties['admin'] -and $i.admin)
    if ($Only -and ($Only -notcontains $tool.id)) { continue }
    if ($i.type -eq 'external') {
        $results.Add([pscustomobject]@{ Tool = $tool.id; Result = 'external'; Detail = "installed by $($i.script)" }); continue
    }
    if ($needsAdmin -ne [bool]$Admin) {
        $results.Add([pscustomobject]@{ Tool = $tool.id; Result = 'other mode'; Detail = $(if ($needsAdmin) { 'run with -Admin' } else { 'run without -Admin' }) }); continue
    }

    $version = if ($tool.PSObject.Properties['version']) { $tool.version } else { '' }
    $existing = Get-InstalledEntry $tool.id
    if ($existing -and -not $Force) {
        $results.Add([pscustomobject]@{ Tool = $tool.id; Result = 'present'; Detail = $existing }); continue
    }

    Write-Step "$($tool.name) $version"
    try {
        $entry = switch ($i.type) {
            'archive'   { Install-Archive $tool }
            'venv'      { Install-Venv $tool }
            'pip'       { Install-Pip $tool }
            'npm'       { Install-Npm $tool }
            'psmodule'  { Install-PsModule $tool }
            'installer' { Install-Interactive $tool }
            'winget'    { Install-Winget $tool }
            default     { throw "Unknown install type '$($i.type)'" }
        }
        Save-InstalledEntry $tool.id $entry $version
        Write-Ok "Installed: $entry"
        $results.Add([pscustomobject]@{ Tool = $tool.id; Result = 'installed'; Detail = $entry })
    } catch {
        Write-Warn "$($tool.name) failed: $($_.Exception.Message)"
        $results.Add([pscustomobject]@{ Tool = $tool.id; Result = 'FAILED'; Detail = $_.Exception.Message.Split("`n")[0] })
    }
}

Write-Step 'Summary'
$results | Format-Table -AutoSize -Wrap | Out-String -Width 160 | Write-Host
$failed = @($results | Where-Object { $_.Result -eq 'FAILED' }).Count
if ($failed) { Write-Host "$failed tool(s) failed. Fix the cause and re-run; finished tools are skipped." -ForegroundColor Yellow; exit 1 }
Write-Host 'Done. Start the console with: powershell -ExecutionPolicy Bypass -File .\console\start-console.ps1' -ForegroundColor Green
