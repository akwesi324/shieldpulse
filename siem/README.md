# SIEM lab

The SIEM is **Elastic**: Elasticsearch and Kibana (Elastic Security), with Winlogbeat and Filebeat, installed natively on Windows and listening on 127.0.0.1 only. Elastic's free tier allows production use. Splunk was the previous SIEM; its setup is kept further down for reference.

```
 This PC
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │  Sysmon, Security (audit policy), PowerShell, Defender ─► Winlogbeat ─┐       │
 │  Suricata eve.json ─────────────────────────────────────► Filebeat ───┤       │
 │                                    write-only API keys                ▼       │
 │                              Elasticsearch 127.0.0.1:9200 ─► Kibana 127.0.0.1:5601
 └──────────────────────────────────────────────────────────────────────────────┘
```

## Elastic (current SIEM)

1. Instrument the machine (Step 1 below, `setup.ps1`).
2. From an **Administrator** PowerShell:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\siem\elastic\install-elastic.ps1
   ```
   You choose the `elastic` superuser password. The script then:
   - **downloads and checks** Elasticsearch, Kibana, Winlogbeat and Filebeat 9.5.6 against Elastic's SHA-512;
   - **stops Splunk** and sets it to Manual start (Splunk is not removed);
   - **configures Elasticsearch** for loopback only, a single node, security on, a 1 GB heap and machine learning off;
   - **sets up the service accounts:** a random password for Kibana's `kibana_system` account, and **write-only API keys** for the Beats, all stored in keystores rather than config files;
   - **loads the Beats setup** (index templates, ingest pipelines and the Winlogbeat dashboards) and starts the Beats as auto-restarting services;
   - **checks** that Windows events are arriving.
3. Verify at any time, without Administrator:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\siem\elastic\verify-elastic.ps1
   ```
4. In the console, go to **Connections**, enter the `elastic` login, and the live cards and watchlist fill in. Open **Kibana → Security** for detection rules, alerts and timelines.

| Component | Where | Runs as |
|---|---|---|
| Elasticsearch | `C:\Program Files\Elastic\elasticsearch`, data in `C:\ProgramData\Elastic` | Service `elasticsearch-service-x64` (automatic) |
| Kibana | `C:\Program Files\Elastic\kibana` | Started from the console when needed (about 1 GB of RAM) |
| Winlogbeat / Filebeat | `C:\Program Files\Elastic\winlogbeat`, `...\filebeat` | Services, restarted automatically on failure |

---

## Previous SIEM: Splunk (reference)

## Folder layout

| Path | Contents |
|---|---|
| `setup.ps1` | Turns on Sysmon, the audit policy and PowerShell logging, then checks that events are being recorded |
| `splunk/install-splunk.ps1` | Installs Splunk, the lab app and the add-ons, then checks that events are arriving |
| `splunk/verify-splunk.ps1` | Checks over the REST API that events arrive and that the add-ons extract fields (no Administrator needed) |
| `splunk/security_labs/` | Splunk app with this lab's indexes (`default/`) and event log inputs (`local/`) |
| `splunk/addons/` | Put the Splunkbase add-on downloads here (excluded from git) |
| `detections/` | Sigma rules, their SPL versions and a safe test for each rule |
| `dashboards/` | Exported Splunk dashboards |

## Step 1: Instrument the machine

Open **PowerShell as Administrator** in the repo folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\siem\setup.ps1
```

The script:

1. Downloads **Sysmon** from Microsoft, checks its signature, and installs it with the [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config).
2. Enables **advanced audit policy**: logons, process creation with full command line, user and group changes, scheduled tasks, and service installs.
3. Enables **PowerShell script block and module logging**.
4. Increases event log sizes (Security 512 MB, Sysmon 256 MB, PowerShell 128 MB).
5. Runs `whoami` and a PowerShell one-liner and confirms they appear in each log.

The original settings are backed up to `C:\ProgramData\SecurityLabs\` on the first run.

| Option | What it does |
|---|---|
| `-SysmonConfigPath .\my.xml` | Use your own Sysmon config instead of the default |
| `-SkipSysmon` | Set up audit and PowerShell logging only |
| `-VerifyOnly` | Make no changes and only run the checks |
| `-Revert` | Restore everything the script changed and uninstall Sysmon if the script installed it |

### Events you should now have

| Log | Event ID | Meaning |
|---|---|---|
| Security | 4624 / 4625 | Successful / failed logon |
| Security | 4688 | Process created (with command line) |
| Security | 4720, 4732 | User created, user added to a local group |
| Security | 4698 | Scheduled task created |
| Sysmon | 1, 3, 11, 13 | Process create, network connection, file create, registry set |
| PowerShell/Operational | 4104 | Script block executed |
| Windows Defender/Operational | 1116 / 1117 | Malware detected / action taken |

### Troubleshooting

- **The 4688 check fails:** a domain Group Policy may be overriding the local audit policy. Run `auditpol /get /subcategory:"Process Creation"` to see the setting in effect.
- **The 4104 check fails:** close and reopen PowerShell. Logging policy only applies to processes started after the change.
- **The Sysmon download fails:** download `Sysmon.zip` from Sysinternals yourself, extract it to `C:\ProgramData\SecurityLabs\Sysmon\`, and run the script again.

## Step 2: Install Splunk

### 2a. Download (needs a free splunk.com account)

| What | Where | Save to |
|---|---|---|
| Splunk Enterprise, Windows `.msi` | [splunk.com/download](https://www.splunk.com/en_us/download/splunk-enterprise.html) | `Downloads\` (the script finds it there) |
| Splunk Add-on for Microsoft Windows | [Splunkbase app 742](https://splunkbase.splunk.com/app/742) | `siem\splunk\addons\` |
| Splunk Add-on for Sysmon | [Splunkbase app 5709](https://splunkbase.splunk.com/app/5709) | `siem\splunk\addons\` |

The installers and add-ons are licensed by Splunk and are excluded from git.

### 2b. Run the installer script (as Administrator)

```powershell
powershell -ExecutionPolicy Bypass -File .\siem\splunk\install-splunk.ps1
```

The script:

1. Checks that the MSI is signed by Splunk, asks you to choose an admin password, and installs Splunk silently. Splunk runs as Local System so it can read the Security log.
2. Copies the [`security_labs`](splunk/security_labs/default/) app into Splunk. The app defines the indexes `wineventlog`, `sysmon`, `powershell` and `defender` (each with a size cap) and the event log inputs.
3. Installs every add-on in `siem\splunk\addons\`.
4. Restarts Splunk and checks that events are arriving in each index.

You can run it again after changing the app or adding add-ons; it skips the install step if Splunk is already there.

Then open **http://localhost:8000** and try:

```spl
index=sysmon EventCode=1 | table _time Image CommandLine ParentImage
```

### 2c. Verify at any time

```powershell
powershell -ExecutionPolicy Bypass -File .\siem\splunk\verify-splunk.ps1
```

A healthy run looks like this:

```
[OK]   wineventlog    16,795 events
[OK]   sysmon         12,325 events
[OK]   powershell      2,004 events
[OK]   defender           63 events
[OK]   Sysmon add-on: CommandLine on Sysmon event 1
[OK]   Windows add-on: EventCode on Security events  (e.g. 4688)
```

### Splunk troubleshooting

- **`wineventlog` is empty but the other indexes have data:** `Splunk_TA_windows` disables the Security and System inputs in its `default/inputs.conf`. Between apps' `default/` folders, Splunk applies settings in ASCII order of the app name, so the uppercase `Splunk_TA_windows` overrides lowercase app names. That's why this lab's inputs live in `security_labs/local/`, which always wins.
- **Field extraction checks fail:** check that both add-ons are in `splunk/addons/`, then re-run `install-splunk.ps1`.
- **Searches show many of Splunk's own processes** (`splunkd`, `splunk-optimize`, `pg_isready`): this is expected, because Splunk is monitoring the machine it runs on. Filter them out in detections, for example `NOT Image="C:\\Program Files\\Splunk\\*"`.

### License note

A new install starts on a **60-day Enterprise trial**. The **Free** license (500 MB/day) removes **alerting** and login. The SOAR integration needs alerts, so request the free **Splunk Developer License** (10 GB/day, renewable every 6 months) instead of switching to Free.

## Next steps

- [x] Instrument the machine (`setup.ps1`)
- [x] Install Splunk, the add-ons and the inputs (`splunk/install-splunk.ps1`)
- [ ] Write the first detections
