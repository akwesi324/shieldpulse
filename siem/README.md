# SIEM lab

Splunk Enterprise (Free license) runs directly on Windows and collects logs from the same machine. There are no VMs and no Docker.

```
 This PC
 ┌──────────────────────────────────────────────────────┐
 │  Sysmon ─┐                                           │
 │  Security log (audit policy) ─┼─► Windows Event Logs ─► Splunk ─► Detections / Dashboards
 │  PowerShell logging ─┘                               │
 │  Defender ─┘                                         │
 └──────────────────────────────────────────────────────┘
```

## Folder layout

| Path | Contents |
|---|---|
| `setup.ps1` | Turns on Sysmon, the audit policy and PowerShell logging, then checks that events are being recorded |
| `splunk/` | Splunk `inputs.conf` and add-on notes *(coming next)* |
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

## Next steps

- [ ] Install Splunk Enterprise and switch to the Free license
- [ ] Add Windows Event Log inputs (`splunk/inputs.conf`)
- [ ] Install the Splunk Add-on for Microsoft Windows and the Sysmon add-on
- [ ] Write the first detections
