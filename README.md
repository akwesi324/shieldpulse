# ShieldPulse

*Formerly security-labs.* A home **SIEM** lab and a separate **SOAR** lab, by MaskedOps. Both run directly on a Windows 11 laptop with no VMs and no Docker, and both fit in 8 GB of RAM if you run one heavy service at a time.

| Lab | Stack | What it shows |
|---|---|---|
| [SIEM](siem/) | **Elastic** (Elasticsearch + Kibana / Elastic Security, free for production use) + Winlogbeat + Filebeat, Sysmon, Windows audit policy and PowerShell logging | Log collection, ECS parsing, ATT&CK-mapped detections, dashboards |
| [SOAR](soar/) | n8n + Python mock alert generator + PowerShell response actions | Alert enrichment, case handling, human approval, automated response |

> **SIEM change:** the SIEM moved from Splunk to Elastic. The Splunk setup is kept in `siem/splunk/` for reference. On machines that had it, Splunk is stopped and set to Manual start, not uninstalled.

## The console

All lab tools are listed in one local web console with a retractable left pane, live status, start/stop buttons and live Elastic data:

```powershell
powershell -ExecutionPolicy Bypass -File .\console\start-console.ps1   # http://127.0.0.1:7700
```

Install the tools with [`tools/install-tools.ps1`](tools/) and the SIEM with [`siem/elastic/install-elastic.ps1`](siem/elastic/). See [tools/README.md](tools/README.md) for the full list and how each download is verified. A read-only Android companion app is in [android/](android/).

## Repository layout

```
shieldpulse/
├── siem/
│   ├── setup.ps1        # instrument this machine (Sysmon, audit policy, PowerShell logging)
│   ├── elastic/         # Elastic SIEM install and verification
│   ├── splunk/          # previous SIEM (kept for reference)
│   ├── detections/      # Sigma rules and safe tests
│   └── dashboards/
├── soar/
│   ├── alert-generator/ # mock alert source (Python)
│   ├── workflows/       # n8n playbook exports
│   └── actions/         # PowerShell response actions
├── tools/               # manifest.json (every tool) + install-tools.ps1
├── console/             # local web console (left tools pane, live data, phone access)
├── android/             # read-only Android companion app
├── scripts/             # start/stop helpers (one lab at a time)
└── docs/
```

## Quick start

```powershell
# As Administrator, from the repo root
powershell -ExecutionPolicy Bypass -File .\siem\setup.ps1                  # 1. instrument the machine
powershell -ExecutionPolicy Bypass -File .\siem\elastic\install-elastic.ps1 # 2. install the Elastic SIEM
```

See [siem/README.md](siem/README.md) for details.

## Safety

- Every test runs on the machine you use every day, so only **benign** attack simulations are used. Windows Defender stays **on**.
- `setup.ps1 -Revert` undoes every change the setup script makes.
- Elasticsearch and Kibana listen on **127.0.0.1 only**. The Beats publish with **write-only API keys**.
- API keys go in a local `.env` file, which is ignored by git. Never commit them.
