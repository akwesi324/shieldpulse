# SOAR lab

n8n (run with `npx`) is the playbook engine, a Python script produces mock alerts, and PowerShell scripts carry out the response actions. Everything runs directly on Windows without Docker, and the lab works independently of the SIEM.

```
 alert-generator (Python) ──webhook──► n8n playbook ──► enrich (VirusTotal / AbuseIPDB / URLScan)
                                              │
                                              ├──► case log + Discord/Slack notification
                                              └──► approval ──► actions/*.ps1 (e.g. firewall block)
```

## Folder layout

| Path | Contents |
|---|---|
| `alert-generator/` | Python script that sends realistic SIEM-style alerts to an n8n webhook |
| `workflows/` | n8n playbook exports (`.json`) you can import directly |
| `actions/` | PowerShell response actions, each with a dry-run mode |

## Planned playbooks

1. **Enrich:** take the IP, hash or URL from the alert, query threat intel and calculate a severity score
2. **Triage and case:** log the case, auto-close benign alerts and escalate the rest
3. **Human approval:** approve or deny before any response action runs
4. **Respond:** block an IP with a Windows Firewall rule
5. **Phishing triage:** parse a `.eml` file, scan its URLs and return a verdict

*Setup instructions will be added as each part is built.*
