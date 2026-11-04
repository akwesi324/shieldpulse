# Lab tools

Every tool used by the SIEM and SOAR labs is defined in [`manifest.json`](manifest.json): its pinned version, download URL, checksum, how to launch it and how to check its status. [`install-tools.ps1`](install-tools.ps1) installs from the manifest, and the [Security Labs Console](../console/) reads the same file.

## Install

```powershell
# 1. Portable and per-user tools (no Administrator needed)
powershell -ExecutionPolicy Bypass -File .\tools\install-tools.ps1

# 2. Network tools: Npcap, Wireshark, Suricata (from an Administrator PowerShell)
powershell -ExecutionPolicy Bypass -File .\tools\install-tools.ps1 -Admin
```

Both modes skip anything already installed, so they're safe to re-run. Use `-Only hayabusa,yara` to install specific tools and `-Force` to reinstall.

Portable tools go to `%LOCALAPPDATA%\SecurityLabs\tools\<id>`, outside the repo. Their paths are recorded in `installed.json` in that folder.

## How downloads are verified

| Check | Used for |
|---|---|
| SHA-256 pinned in the manifest (from the vendor's GitHub release or SHASUMS file) | Hayabusa, Chainsaw, YARA, Velociraptor, CyberChef, SigmaHQ rules, DeepBlueCLI, Node.js |
| Authenticode signature (the vendor publishes no hash) | Sysinternals Suite (Microsoft), Npcap (Nmap Software LLC) |
| Vendor's published MD5 | Emerging Threats Open rules |
| winget's manifest hash | Wireshark, Suricata |
| PowerShell Gallery / PyPI / npm registry | Invoke-AtomicRedTeam, pip packages, n8n |

If a check fails, the file is deleted and that tool is skipped.

## Tools

| Area | Tool | Version | Purpose |
|---|---|---|---|
| SIEM | Elasticsearch + Kibana (Elastic Security) | 9.5.6 | Event storage, search, detection rules, dashboards (installed by `siem\elastic\install-elastic.ps1`) |
| SIEM | Winlogbeat + Filebeat | 9.5.6 | Ship Windows event logs and Suricata `eve.json` to Elasticsearch with write-only API keys |
| SIEM | Sysmon | Sysinternals | Endpoint telemetry (installed by `siem\setup.ps1`) |
| Detection & Hunting | Sigma CLI | pip | Convert Sigma rules to Elasticsearch (Lucene or ES\|QL) or SPL |
| Detection & Hunting | SigmaHQ rules | r2026-07-01 | 3,000+ community detection rules |
| Detection & Hunting | Hayabusa | 4.3.1 | Event log hunting and timelines with Sigma |
| Detection & Hunting | Chainsaw | 2.17.1 | Fast event log search and Sigma hunting |
| Detection & Hunting | DeepBlueCLI | 2eecc65 | Suspicious-activity detection in event logs |
| Detection & Hunting | YARA | 4.6.0 | Malware pattern matching |
| Attack Simulation & DFIR | Atomic Red Team | 2.3.0 | ATT&CK test cases (benign tests only on this machine) |
| Attack Simulation & DFIR | Sysinternals Suite | Microsoft | Process Explorer, Autoruns, TCPView, Procmon |
| Attack Simulation & DFIR | Velociraptor | 0.77.3 | Endpoint visibility and DFIR collection |
| SOAR & Threat Intel | n8n | 2.45.7 | Playbook engine (runs on a private Node 24) |
| SOAR & Threat Intel | CyberChef | 11.5.0 | Offline decoding and analysis, served by the console |
| SOAR & Threat Intel | SOAR Python toolkit | pip | requests, vt-py, python-dotenv |
| Network Monitoring | Npcap | 1.90 | Packet capture driver |
| Network Monitoring | Wireshark | 4.6.9 | Packet analysis |
| Network Monitoring | Suricata + ET Open | 7.0.10 | Network IDS; Filebeat ships alerts to Elasticsearch (`event.module: suricata`) |

## Adding a tool

Add an entry to `manifest.json` with `install` (one of `archive`, `pip`, `npm`, `psmodule`, `winget`, `installer`, `external`), optional `detect` and `status` checks, and `actions` (`web`, `gui`, `terminal`, `folder`, `service`, `kill`). Run the installer and refresh the console; no code changes are needed.
