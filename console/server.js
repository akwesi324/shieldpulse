'use strict';
/**
 * Security Labs Console - local control panel for the SIEM/SOAR lab tools.
 *
 * - Serves the UI (public/) and CyberChef (/cyberchef/) on http://127.0.0.1:7700 only.
 * - GET  /api/state                     -> tools from tools/manifest.json + live status + RAM
 * - POST /api/tools/:id/actions/:index  -> runs one action that is defined in the manifest
 *
 * Safety: binds to loopback; rejects requests whose Host/Origin is not this console
 * (blocks DNS rebinding and cross-site requests); POSTs need a per-run random token that is
 * embedded in the page; only manifest-defined actions can run - never arbitrary commands.
 * No dependencies: Node's standard library only.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFile, spawn } = require('child_process');

const PORT = Number(process.env.LAB_CONSOLE_PORT || 7700);
const HOST = '127.0.0.1';
const REPO = path.resolve(__dirname, '..');
const MANIFEST_FILE = path.join(REPO, 'tools', 'manifest.json');
const TOOLS = path.join(process.env.LOCALAPPDATA || os.homedir(), 'SecurityLabs', 'tools');
const INSTALLED_FILE = path.join(TOOLS, 'installed.json');
const PF = process.env.ProgramFiles || 'C:\\Program Files';
const PUBLIC = path.join(__dirname, 'public');
const TOKEN = crypto.randomBytes(24).toString('hex');
const ALLOWED_HOSTS = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`]);

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.txt': 'text/plain; charset=utf-8',
  '.wasm': 'application/wasm', '.map': 'application/json',
};

// ---------------------------------------------------------------------------
// Manifest, installed.json and token expansion

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '')); }
  catch { return fallback; }
}

function loadManifest() { return readJson(MANIFEST_FILE, { categories: [], tools: [] }); }
function loadInstalled() { return readJson(INSTALLED_FILE, {}); }

function expand(value, tool, installed) {
  if (Array.isArray(value)) return value.map((v) => expand(v, tool, installed));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = expand(v, tool, installed);
    return out;
  }
  if (typeof value !== 'string') return value;
  const entryOf = (id) => (installed[id] && installed[id].entry) || null;
  return value.replace(/\{(ENTRY:[\w-]+|ENTRYDIR|ENTRY|DIR|TOOLS|REPO|PF)\}/g, (match, key) => {
    if (key.startsWith('ENTRY:')) return entryOf(key.slice(6)) || match;
    switch (key) {
      case 'TOOLS': return TOOLS;
      case 'REPO': return REPO;
      case 'PF': return PF;
      case 'DIR': return path.join(TOOLS, tool.id);
      case 'ENTRY': return entryOf(tool.id) || match;
      case 'ENTRYDIR': return entryOf(tool.id) ? path.dirname(entryOf(tool.id)) : path.join(TOOLS, tool.id);
      default: return match;
    }
  });
}

// ---------------------------------------------------------------------------
// PowerShell helpers

const psQuote = (s) => `'${String(s).replace(/'/g, "''")}'`;
const encode = (script) => Buffer.from(script, 'utf16le').toString('base64');

function runPowerShell(script, timeoutMs = 20000) {
  return new Promise((resolve) => {
    execFile('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encode(script)],
      { windowsHide: true, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => resolve({ ok: !err, stdout: String(stdout), stderr: String(stderr || (err && err.message) || '') }));
  });
}

/** Runs a script in a hidden, elevated PowerShell (UAC prompt) and waits for it. */
function runElevated(script) {
  return runPowerShell(
    `Start-Process powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','${encode(script)}'`,
    120000);
}

// ---------------------------------------------------------------------------
// Live status (services, processes, web UIs), cached briefly

let systemCache = { at: 0, data: null, pending: null };

async function getSystemSnapshot(serviceNames) {
  if (systemCache.data && Date.now() - systemCache.at < 4000) return systemCache.data;
  if (systemCache.pending) return systemCache.pending;
  const names = serviceNames.filter((n) => /^[\w.-]+$/.test(n));
  const script = `
$ErrorActionPreference = 'SilentlyContinue'
$svc = @(Get-Service -Name ${names.map(psQuote).join(',') || "'__none__'"} | ForEach-Object { @{ name = $_.Name; status = "$($_.Status)" } })
$proc = @(Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath | ForEach-Object { @{ id = $_.ProcessId; name = $_.Name; path = $_.ExecutablePath } })
@{ services = $svc; processes = $proc } | ConvertTo-Json -Depth 4 -Compress`;
  systemCache.pending = runPowerShell(script).then(({ stdout }) => {
    let parsed = { services: [], processes: [] };
    try { parsed = JSON.parse(stdout); } catch { /* keep empty */ }
    const services = new Map((parsed.services || []).map((s) => [s.name.toLowerCase(), s.status]));
    const procNames = new Set((parsed.processes || []).map((p) => String(p.name || '').toLowerCase()));
    const procPaths = new Set((parsed.processes || []).filter((p) => p.path).map((p) => p.path.toLowerCase()));
    const procs = (parsed.processes || []).map((p) => ({ id: Number(p.id), name: String(p.name || ''), path: p.path || '' }));
    const pids = new Set(procs.map((p) => p.id));
    systemCache = { at: Date.now(), data: { services, procNames, procPaths, pids, procs }, pending: null };
    return systemCache.data;
  }).catch(() => { systemCache.pending = null; return { services: new Map(), procNames: new Set(), procPaths: new Set(), pids: new Set(), procs: [] }; });
  return systemCache.pending;
}

// Windows (terminals, GUI tools) opened by this console, per tool: toolId -> Map(pid -> { admin }).
// This is what lets "Stop running" close a CLI tool's terminal as well as stop services.
const sessions = new Map();

function trackSession(toolId, pid, admin) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  if (!sessions.has(toolId)) sessions.set(toolId, new Map());
  sessions.get(toolId).set(pid, { admin });
}

function liveSessions(toolId, sys) {
  const map = sessions.get(toolId);
  if (!map) return [];
  for (const pid of [...map.keys()]) if (!sys.pids.has(pid)) map.delete(pid); // window was closed
  return [...map.entries()].map(([pid, info]) => ({ pid, ...info }));
}

/** Evaluates a tool's status checks against a snapshot. Returns null if the tool has none. */
function isRunning(t, sys) {
  const checks = [];
  if (t.status) {
    if (t.status.service) checks.push(sys.services.get(t.status.service.toLowerCase()) === 'Running');
    if (t.status.processName) checks.push(sys.procNames.has(t.status.processName.toLowerCase()));
    if (t.status.processNames) checks.push(t.status.processNames.some((n) => sys.procNames.has(n.toLowerCase())));
    if (t.status.exePath) checks.push(sys.procPaths.has(t.status.exePath.toLowerCase()));
  }
  const hasSessions = liveSessions(t.id, sys).length > 0;
  if (!checks.length && !hasSessions) return t.status ? false : null;
  return hasSessions || checks.some(Boolean);
}

function probeUrl(url) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve(false); }
    const loopback = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(u.hostname);
    if (!loopback) return resolve(false); // only probe local services
    const lib = u.protocol === 'https:' ? https : http;
    // Local lab services (Velociraptor) use self-signed certificates; this probe only checks reachability.
    const req = lib.get(url, { timeout: 1500, rejectUnauthorized: false }, (res) => { res.resume(); resolve(true); });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

async function buildState() {
  const manifest = loadManifest();
  const installed = loadInstalled();
  const serviceNames = new Set();
  for (const t of manifest.tools) {
    if (t.detect && t.detect.service) serviceNames.add(t.detect.service);
    if (t.status && t.status.service) serviceNames.add(t.status.service);
  }
  const sys = await getSystemSnapshot([...serviceNames]);

  const tools = await Promise.all(manifest.tools.map(async (raw) => {
    const t = expand(raw, raw, installed);
    const entry = installed[t.id] && installed[t.id].entry;
    const isInstalled = Boolean(
      (entry && (entry.startsWith('service:') || fs.existsSync(entry))) ||
      (t.detect && t.detect.path && fs.existsSync(t.detect.path)) ||
      (t.detect && t.detect.service && sys.services.has(t.detect.service.toLowerCase())));

    // null = nothing to track (e.g. a CLI tool with no open terminal and no status checks).
    let running = isRunning(t, sys);
    if (running !== true && t.status && t.status.url && await probeUrl(t.status.url)) running = true;

    const i = t.install || {};
    let installHint = 'powershell -ExecutionPolicy Bypass -File .\\tools\\install-tools.ps1';
    if (i.type === 'external') installHint = `powershell -ExecutionPolicy Bypass -File .\\${i.script}   (as Administrator)`;
    else if (i.admin) installHint += ' -Admin   (as Administrator)';

    return {
      id: t.id, name: t.name, category: t.category, version: t.version || '', hidden: Boolean(t.hidden),
      description: t.description || '', docs: t.docs || '', installed: isInstalled, running, installHint,
      installedVersion: installed[t.id] ? installed[t.id].version : null,
      // Stop actions are folded into the single "Stop running" button.
      actions: (t.actions || []).map((a, index) => ({
        index, label: a.label, type: a.type, url: a.url || null, primary: Boolean(a.primary), admin: Boolean(a.admin), stop: Boolean(a.stop),
      })).filter((a) => !a.stop),
      canStop: running === true,
      examples: t.examples || [],
    };
  }));

  return {
    system: {
      hostname: os.hostname(),
      totalMemMB: Math.round(os.totalmem() / 1048576),
      freeMemMB: Math.round(os.freemem() / 1048576),
      toolsDir: TOOLS,
    },
    categories: manifest.categories,
    tools: tools.filter((t) => !t.hidden),
  };
}

// ---------------------------------------------------------------------------
// Actions

async function runAction(toolId, index) {
  const manifest = loadManifest();
  const installed = loadInstalled();
  const raw = manifest.tools.find((t) => t.id === toolId);
  if (!raw) return { status: 404, body: { error: 'Unknown tool' } };
  const t = expand(raw, raw, installed);
  const a = (t.actions || [])[index];
  if (!a) return { status: 404, body: { error: 'Unknown action' } };
  if (/\{(ENTRY|ENTRYDIR|ENTRY:[\w-]+)\}/.test(JSON.stringify(a))) {
    return { status: 409, body: { error: `${t.name} is not installed yet.` } };
  }
  systemCache.at = 0; // refresh status on next poll

  switch (a.type) {
    case 'web':
      return { status: 200, body: { ok: true, message: `Opening ${a.url}` } };

    case 'folder': {
      if (!fs.existsSync(a.path)) return { status: 409, body: { error: `Folder not found: ${a.path}` } };
      spawn('explorer.exe', [a.path], { detached: true, stdio: 'ignore' }).unref();
      return { status: 200, body: { ok: true, message: `Opened ${a.path}` } };
    }

    case 'gui': {
      const args = (a.args || []).map(psQuote).join(',');
      const script = `(Start-Process -FilePath ${psQuote(a.path)}${args ? ` -ArgumentList ${args}` : ''}${a.admin ? ' -Verb RunAs' : ''} -PassThru).Id`;
      const r = await runPowerShell(script);
      if (r.ok) trackSession(t.id, parseInt(r.stdout, 10), Boolean(a.admin));
      return r.ok ? { status: 200, body: { ok: true, message: `Launched ${a.label}` } }
        : { status: 500, body: { error: cancelled(r.stderr) } };
    }

    case 'terminal': {
      const inner = [
        `$Host.UI.RawUI.WindowTitle = ${psQuote(`Security Labs - ${t.name}`)}`,
        `Set-Location -LiteralPath ${psQuote(a.cwd || REPO)}`,
        `Write-Host ${psQuote(`${t.name} - ${a.label}`)} -ForegroundColor Cyan`,
        a.command || '',
      ].join('; ');
      const script = `(Start-Process powershell.exe -ArgumentList '-NoExit','-ExecutionPolicy','Bypass','-EncodedCommand','${encode(inner)}'${a.admin ? ' -Verb RunAs' : ''} -PassThru).Id`;
      const r = await runPowerShell(script);
      if (r.ok) trackSession(t.id, parseInt(r.stdout, 10), Boolean(a.admin));
      return r.ok ? { status: 200, body: { ok: true, message: `Opened ${a.admin ? 'an elevated ' : 'a '}terminal for ${t.name}` } }
        : { status: 500, body: { error: cancelled(r.stderr) } };
    }

    case 'service': {
      if (!/^[\w.-]+$/.test(a.service) || !['start', 'stop'].includes(a.op)) return { status: 400, body: { error: 'Bad service action' } };
      const verb = a.op === 'start' ? 'Start-Service' : 'Stop-Service';
      const r = await runElevated(`${verb} -Name ${psQuote(a.service)}`);
      return r.ok ? { status: 200, body: { ok: true, message: `${a.op === 'start' ? 'Started' : 'Stopped'} ${t.name}` } }
        : { status: 500, body: { error: cancelled(r.stderr) } };
    }

    case 'kill':
      return stopTool(t.id);

    default:
      return { status: 400, body: { error: `Unsupported action type '${a.type}'` } };
  }
}

// Fast native helpers for stopping (each PowerShell start costs seconds on a busy machine).
function execQuick(file, args, timeout = 60000) { // generous: a fully loaded 8 GB laptop is slow
  return new Promise((resolve) => {
    execFile(file, args, { windowsHide: true, timeout }, (err, stdout) =>
      resolve({ ok: !err, code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, stdout: String(stdout || '') }));
  });
}

/**
 * taskkill a target ({ pid } or { image }) with its child processes.
 * Result: 'killed' (exit 0), 'absent' (exit 128: no such process) or 'denied' (anything else,
 * typically an elevated process that needs Administrator).
 */
async function killTarget(target) {
  const args = ['/T', '/F', ...(target.pid ? ['/PID', String(target.pid)] : ['/IM', target.image])];
  const { code } = await execQuick('taskkill.exe', args);
  return code === 0 ? 'killed' : code === 128 ? 'absent' : 'denied';
}

async function runningServices(names) {
  const out = [];
  for (const n of names) {
    const { stdout } = await execQuick('sc.exe', ['query', n]);
    if (/STATE\s+:\s+\d+\s+(RUNNING|START_PENDING|STOP_PENDING)/.test(stdout)) out.push(n);
  }
  return out;
}

/**
 * "Stop running": stops the tool's services and processes and closes every window this
 * console opened for it. Kills what it can without elevation (taskkill), then, only if
 * something is left (elevated processes, services), does the rest in one elevated step.
 */
async function stopTool(toolId) {
  const manifest = loadManifest();
  const installed = loadInstalled();
  const raw = manifest.tools.find((t) => t.id === toolId);
  if (!raw) return { status: 404, body: { error: 'Unknown tool' } };
  const t = expand(raw, raw, installed);
  const serviceNames = manifest.tools.flatMap((x) => [x.detect && x.detect.service, x.status && x.status.service]).filter(Boolean);
  // Targets: windows this console opened, processes named by stop actions, services.
  const targets = [...(sessions.get(t.id) || new Map()).keys()].map((pid) => ({ pid }));
  const services = [];
  for (const a of (t.actions || []).filter((x) => x.stop)) {
    if (a.type === 'service' && /^[\w.-]+$/.test(a.service)) services.push(a.service);
    if (a.type === 'kill' && (a.processNames || a.processName)) {
      for (const n of (a.processNames || [a.processName])) if (/^[\w.-]+$/.test(n)) targets.push({ image: n });
    }
    if (a.type === 'kill' && a.exePath) {
      // taskkill cannot match by path; use the status snapshot (refreshed every few seconds by the UI poll).
      const sys = systemCache.data || await getSystemSnapshot(serviceNames);
      sys.procs.filter((p) => p.path.toLowerCase() === a.exePath.toLowerCase()).forEach((p) => targets.push({ pid: p.id }));
    }
  }

  // 1. Without elevation: kill process trees; services are checked in parallel.
  const [results, activeServices] = await Promise.all([
    Promise.all(targets.map(killTarget)),
    runningServices(services),
  ]);
  const denied = targets.filter((_, i) => results[i] === 'denied');
  const killedAny = results.includes('killed');

  if (!killedAny && !denied.length && !activeServices.length) {
    sessions.delete(t.id);
    const webUp = t.status && t.status.url && await probeUrl(t.status.url);
    return { status: 409, body: { error: webUp ? `${t.name} is running outside the console; stop it from its own window.` : `${t.name} is not running.` } };
  }

  // 2. Elevated (one UAC prompt) for what is left: elevated processes and services.
  if (denied.length || activeServices.length) {
    const lines = denied.map((d) => `& taskkill.exe /T /F ${d.pid ? `/PID ${d.pid}` : `/IM ${psQuote(d.image)}`} 2>$null | Out-Null`);
    for (const s of activeServices) lines.push(`Stop-Service -Name ${psQuote(s)} -Force -ErrorAction SilentlyContinue`);
    const r = await runElevated(lines.join('\n'));
    if (!r.ok) return { status: 500, body: { error: cancelled(r.stderr) } };
    const leftServices = await runningServices(activeServices);
    if (leftServices.length) return { status: 500, body: { error: `${t.name} is still running (${leftServices.join(', ')}).` } };
  }

  systemCache.at = 0;
  sessions.delete(t.id);
  return { status: 200, body: { ok: true, message: `Stopped ${t.name}` } };
}

function firstLine(text) { return String(text || 'Failed').trim().split(/\r?\n/)[0].slice(0, 300); }
function cancelled(text) { return /canceled by the user|cancelled by the user/i.test(text) ? 'Cancelled at the UAC prompt.' : firstLine(text); }

// ---------------------------------------------------------------------------
// HTTP

function send(res, status, body, headers = {}) {
  const isJson = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, {
    'Content-Type': isJson ? MIME['.json'] : (headers['Content-Type'] || 'text/plain; charset=utf-8'),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(isJson ? JSON.stringify(body) : body);
}

function serveFile(res, baseDir, relPath, extraHeaders = {}) {
  const resolved = path.resolve(baseDir, '.' + path.sep + relPath);
  if (!resolved.startsWith(path.resolve(baseDir) + path.sep) && resolved !== path.resolve(baseDir)) {
    return send(res, 403, 'Forbidden');
  }
  fs.readFile(resolved, (err, data) => {
    if (err) return send(res, 404, 'Not found');
    send(res, 200, data, { 'Content-Type': MIME[path.extname(resolved).toLowerCase()] || 'application/octet-stream', ...extraHeaders });
  });
}

const PAGE_CSP = "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";

const server = http.createServer(async (req, res) => {
  // Reject anything not addressed to this console (DNS rebinding) or sent from another site.
  if (!ALLOWED_HOSTS.has(String(req.headers.host || '').toLowerCase())) return send(res, 421, 'Misdirected request');
  const origin = req.headers.origin;
  if (origin && !ALLOWED_HOSTS.has(origin.replace(/^https?:\/\//, '').toLowerCase())) return send(res, 403, 'Cross-origin request refused');

  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = decodeURIComponent(url.pathname);

  try {
    if (req.method === 'GET' && p === '/') {
      const html = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8').replace('__CONSOLE_TOKEN__', TOKEN);
      return send(res, 200, html, { 'Content-Type': MIME['.html'], 'Content-Security-Policy': PAGE_CSP });
    }
    if (req.method === 'GET' && p === '/api/state') return send(res, 200, await buildState());

    const m = p.match(/^\/api\/tools\/([\w-]+)\/(?:actions\/(\d+)|(stop))$/);
    if (m && req.method === 'POST') {
      if (req.headers['x-console-token'] !== TOKEN) return send(res, 403, { error: 'Missing or invalid console token. Reload the page.' });
      const r = m[3] ? await stopTool(m[1]) : await runAction(m[1], Number(m[2]));
      return send(res, r.status, r.body);
    }

    if (req.method === 'GET' && (p === '/cyberchef' || p.startsWith('/cyberchef/'))) {
      const entry = (loadInstalled().cyberchef || {}).entry;
      if (!entry || !fs.existsSync(entry)) return send(res, 404, 'CyberChef is not installed. Run tools\\install-tools.ps1.');
      if (p === '/cyberchef') return send(res, 301, '', { Location: '/cyberchef/' });
      const rel = p.slice('/cyberchef/'.length) || path.basename(entry);
      return serveFile(res, path.dirname(entry), rel);
    }

    if (req.method === 'GET' && /^\/[\w.-]+\.(js|css|svg|png|ico)$/.test(p)) {
      return serveFile(res, PUBLIC, p.slice(1), { 'Content-Security-Policy': PAGE_CSP });
    }
    send(res, 404, 'Not found');
  } catch (err) {
    send(res, 500, { error: err.message });
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') console.error(`Port ${PORT} is in use. Is the console already running? Open http://127.0.0.1:${PORT}`);
  else console.error(err);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`Security Labs Console: http://127.0.0.1:${PORT}`);
  console.log(`Tools folder: ${TOOLS}`);
});
