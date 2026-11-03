# Security Labs for Android

A **read-only** Android app for viewing your lab from your phone while it's on the same Wi-Fi as your PC. It shows live Splunk ingestion, watchlist hits, Suricata IDS alerts, n8n playbook runs, PC memory, and the status of every lab tool.

The app can't start or stop tools, or change any settings. Those controls stay in the console on your PC.

```
 Phone (Security Labs app)                         PC (Security Labs Console)
 ┌──────────────────────────┐   HTTPS, pinned     ┌──────────────────────────────────────┐
 │ bundled UI (WebView)     │   certificate,      │ 127.0.0.1:7700   full console (PC)   │
 │ native HTTPS client ─────┼── bearer token ───► │ 0.0.0.0:7743     phone server        │
 │ token + pin in private   │   home Wi-Fi only   │                  GET /m/state (view) │
 │ app storage              │                     │                  POST /m/pair        │
 └──────────────────────────┘                     └──────────────────────────────────────┘
```

## Install on your phone

1. Copy `android\dist\SecurityLabs-1.0.0.apk` to your phone, or download it from wherever you've put it.
2. Open it and allow **Install unknown apps** for the app you opened it with. The APK is signed with your own key, not by Google Play.
3. On the PC, open the console (`http://127.0.0.1:7700`) and go to **Connections → Phone access**. Turn it on, then click **Pair a phone**.
   - If Windows Firewall asks about Node.js, allow it on **Private networks** only.
4. In the app, enter the **PC address** shown on the PC.
5. Check that the **fingerprint** on the phone matches the one on the PC, then tap **It matches**.
6. Enter the **6-digit code**.

To remove a phone, click **Revoke** next to it under Phone access on the PC. The phone loses access straight away.

## Security model

| Measure | Details |
|---|---|
| Read-only by construction | The phone server has exactly two routes: `POST /m/pair` and `GET /m/state`. No route exists that could start or stop a tool. |
| Home network only | The phone server answers only private addresses (192.168.x, 10.x, 172.16–31.x). Phone access is off until you turn it on. |
| Encrypted and pinned | HTTPS (TLS 1.2+) with a certificate generated on your PC. At pairing you compare its fingerprint on both screens. After that the app trusts only that exact certificate, so a lookalike server is refused. |
| Pairing code | 6 digits, single use, valid for 5 minutes. After 5 wrong tries the code is cancelled. The code is only sent after the certificate is pinned. |
| Per-phone tokens | Each phone gets its own random 256-bit token. The PC stores only its SHA-256 hash, and you can revoke each phone separately. |
| App hardening | The app can only load its own bundled pages, under a strict content security policy. Other links open in your browser. It has no backup and no cleartext HTTP. Its only permission is internet access. |

## Build

The app is built with the Android SDK tools directly (`aapt2 → javac → d8 → zipalign → apksigner`), with no Gradle and no Android Studio:

```powershell
powershell -ExecutionPolicy Bypass -File .\android\setup-toolchain.ps1   # once: JDK 21 + Android SDK 35
powershell -ExecutionPolicy Bypass -File .\android\build-apk.ps1         # -> android\dist\SecurityLabs-1.0.0.apk
```

To release an update, pass a higher `-VersionCode` and a new `-VersionName`.

The signing key is created on the first build at `%LOCALAPPDATA%\SecurityLabs\android\signing\`, and its password is stored encrypted for your Windows account. **Back it up.** Android only installs updates that are signed with the same key.

## Layout

| Path | Contents |
|---|---|
| `app/AndroidManifest.xml` | App manifest. The only permission is `INTERNET`. |
| `app/java/.../MainActivity.java` | WebView host and the certificate-pinning HTTPS bridge |
| `app/assets/` | The app's interface (HTML/CSS/JS) |
| `app/res/` | Theme, colors, and the adaptive launcher icon (shield + pulse) |
| `setup-toolchain.ps1`, `build-apk.ps1` | Toolchain install and build scripts |
