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

## Security

- Listens on **127.0.0.1 only**, not reachable from the network.
- Rejects requests whose `Host` or `Origin` isn't the console itself. This blocks DNS rebinding and other websites calling it.
- Actions need a random token generated at each start and embedded in the page.
- Runs **only actions defined in `tools/manifest.json`**; there is no endpoint that runs arbitrary commands.
- No npm dependencies: Node's standard library only.

All tools and actions come from [`tools/manifest.json`](../tools/manifest.json), so edit that file to add or change tools.
