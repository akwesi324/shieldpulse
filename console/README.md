# Security Labs Console

A local web control panel for every lab tool. A **retractable pane on the left** lists all tools by area with live status. Select a tool to start or stop it, open its UI, launch a terminal ready to use it, or copy example commands.

```powershell
powershell -ExecutionPolicy Bypass -File .\console\start-console.ps1
# or: cd console; npm start      ->  http://127.0.0.1:7700
```

| Feature | Details |
|---|---|
| Retractable pane | Click the chevron or press `[` to collapse it to a narrow rail that still shows each tool's status. The choice is remembered. On phones the pane is a drawer. |
| Live status | Green = running, blue = installed, hollow = not installed. Refreshes every 5 seconds from Windows services, processes and local web UIs. |
| Stop running | A red stop button appears beside every running tool in the pane, and a **Stop running** button on its page. It stops the tool's services and processes and closes any terminal or GUI window the console opened for it. It kills what it can without Administrator, then shows one UAC prompt only if something is elevated (Splunk, Sysmon, Suricata, admin terminals). |
| Actions | Open web UIs (Splunk, n8n, Velociraptor, CyberChef), launch GUI tools, open a terminal in the tool's folder, start or stop services. Admin actions show a UAC prompt. |
| Memory meter | RAM in use, shown in the pane footer, so you can run one heavy service at a time on 8 GB. |
| CyberChef | Served locally at `/cyberchef/`, fully offline. |
| Live data | Overview cards for Splunk, the watchlist, Suricata and n8n, refreshed automatically. The Splunk page shows ingestion per index (last 15 min / 24 h / latest event) and the watchlist. The Suricata page shows the latest IDS alerts from `eve.json`. The n8n page shows workflows and recent executions. |
| Watchlist | [`watches.json`](watches.json) holds 24-hour counts of key security events (failed logons, new accounts, admin group changes, scheduled tasks, service installs, encoded PowerShell, log clearing, Defender and Suricata alerts), each mapped to ATT&CK with one-click "open in Splunk". Edit the file to add your own searches. |
| Connections | Save the Splunk login and an n8n API key once (pane footer, **Connections**). |

## Live data and connections

| Source | How the console reads it | Refresh |
|---|---|---|
| Splunk | REST API on `127.0.0.1:8089`: server info, health, `tstats` per index, one search per watch | 90 s |
| Suricata | Reads the tail of `C:\Program Files\Suricata\log\eve.json` (last 2 MB) | 10 s |
| n8n | `/healthz`, plus `/api/v1/workflows` and `/api/v1/executions` with the API key | 20 s |

Sources are refreshed in the background and cached, so the page loads instantly and the tools aren't overloaded. Each source shows a clear state: **Connected**, **Needs connection**, **Not running** or **Error**.

**Credentials:**
- Before saving, each one is checked against the running service.
- They're encrypted with **Windows DPAPI** (`ConvertFrom-SecureString`), so only your Windows account on this PC can decrypt them. They're stored in `%LOCALAPPDATA%\SecurityLabs\console\secrets.json`, outside the repo.
- They're passed to the encryption helper on stdin, never on a command line.
- They're never returned to the browser, and **Forget** deletes them.

## Security

- Listens on **127.0.0.1 only**, not reachable from the network.
- Rejects requests whose `Host` or `Origin` isn't the console itself. This blocks DNS rebinding and other websites calling it.
- Actions need a random token generated at each start and embedded in the page.
- Runs **only actions defined in `tools/manifest.json`**; there is no endpoint that runs arbitrary commands.
- No npm dependencies: Node's standard library only.

All tools and actions come from [`tools/manifest.json`](../tools/manifest.json), so edit that file to add or change tools.
