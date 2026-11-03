# security-labs

A home **SIEM** lab and a separate **SOAR** lab. Both run directly on a Windows 11 laptop with no VMs and no Docker, and both fit in 8 GB of RAM if you run one at a time.

| Lab | Stack | What it shows |
|---|---|---|
| [SIEM](siem/) | Splunk Enterprise (Free) + Sysmon + Windows audit policy + PowerShell logging | Log collection, parsing, ATT&CK-mapped detections, dashboards |
| [SOAR](soar/) | n8n + Python mock alert generator + PowerShell response actions | Alert enrichment, case handling, human approval, automated response |

## Security Labs Console

All lab tools are listed in one local web console with a retractable left pane, live status and start/stop buttons:

```powershell
powershell -ExecutionPolicy Bypass -File .\console\start-console.ps1   # http://127.0.0.1:7700
```

Install the tools with [`tools/install-tools.ps1`](tools/). See [tools/README.md](tools/README.md) for the full list and how each download is verified.

## Repository layout

```
security-labs/
├── siem/
│   ├── setup.ps1        # instrument this machine (Sysmon, audit policy, PowerShell logging)
│   ├── splunk/          # Splunk inputs and add-on configuration
│   ├── detections/      # Sigma rules, SPL versions and safe tests
│   └── dashboards/      # exported Splunk dashboards
├── soar/
│   ├── alert-generator/ # mock alert source (Python)
│   ├── workflows/       # n8n playbook exports
│   └── actions/         # PowerShell response actions
├── tools/               # manifest.json (every tool) + install-tools.ps1
├── console/             # Security Labs Console (local web UI, left tools pane)
├── scripts/             # start/stop helpers (one lab at a time)
└── docs/                # architecture notes and screenshots
```

## Quick start

```powershell
# As Administrator, from the repo root
powershell -ExecutionPolicy Bypass -File .\siem\setup.ps1
```

See [siem/README.md](siem/README.md) for details.

## Safety

- Every test runs on the machine you use every day, so only **benign** attack simulations are used. Windows Defender stays **on**.
- `setup.ps1 -Revert` undoes every change the setup script makes.
- API keys go in a local `.env` file, which is ignored by git. Never commit them.
