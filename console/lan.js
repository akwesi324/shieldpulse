'use strict';
/**
 * Phone access: a READ-ONLY HTTPS server on the home network (port 7743) for the Android app.
 *
 * - Off by default; turned on from the console's Connections page (loopback only).
 * - Exactly two routes: POST /m/pair and GET /m/state. There is no route that starts or stops
 *   tools or changes settings, so a paired phone can only view.
 * - Accepts connections from private network addresses only (home Wi-Fi), never the internet.
 * - TLS with a self-signed certificate generated on this PC (AES-protected PFX, password stored
 *   DPAPI-encrypted). The app pins the certificate's SHA-256 fingerprint at pairing, after you
 *   confirm the short fingerprint shown on both screens matches.
 * - Pairing: a one-time 6-digit code shown on the PC, valid 5 minutes, 5 attempts. Each phone
 *   gets its own random token; only a SHA-256 hash of it is stored. Phones can be revoked.
 */
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const secrets = require('./secrets');

const PORT = Number(process.env.LAB_PHONE_PORT || 7743);
const DIR = path.join(process.env.LOCALAPPDATA || os.homedir(), 'SecurityLabs', 'console');
const CONFIG_FILE = path.join(DIR, 'lan.json');
const DEVICES_FILE = path.join(DIR, 'devices.json');
const PFX_FILE = path.join(DIR, 'lan-cert.pfx');

const PAIR_TTL_MS = 5 * 60 * 1000;
const PAIR_MAX_ATTEMPTS = 5;

let server = null;
let pairing = null; // { code, expiresAt, attempts }
let deps = null;    // { buildState, getLive }

// ---------------------------------------------------------------------------
// Storage

function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } }
function writeJson(file, data) {
  fs.mkdirSync(DIR, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 });
}
const loadConfig = () => readJson(CONFIG_FILE, { enabled: false });
const saveConfig = (c) => writeJson(CONFIG_FILE, c);
const loadDevices = () => readJson(DEVICES_FILE, []);
const saveDevices = (d) => writeJson(DEVICES_FILE, d);

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const shortFingerprint = (fp) => (fp ? fp.slice(0, 12).toUpperCase().match(/.{4}/g).join('-') : null);

// ---------------------------------------------------------------------------
// Certificate (generated once with New-SelfSignedCertificate, exported as AES PFX)

function runPs(script, input) {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { windowsHide: true });
    let out = ''; let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(err.trim().split(/\r?\n/)[0] || `exit ${code}`))));
    child.stdin.end(input || '');
  });
}

async function ensureCertificate() {
  const config = loadConfig();
  if (config.fingerprint && fs.existsSync(PFX_FILE)) {
    const s = await secrets.load('lan-cert');
    if (s && s.password) return { pfx: fs.readFileSync(PFX_FILE), passphrase: s.password, fingerprint: config.fingerprint };
  }
  const password = crypto.randomBytes(24).toString('base64url');
  const script = `$ErrorActionPreference = 'Stop'
$pw = ConvertTo-SecureString ([Console]::In.ReadToEnd().Trim()) -AsPlainText -Force
$c = New-SelfSignedCertificate -Subject 'CN=Security Labs Console' -FriendlyName 'Security Labs Console (phone access)' -CertStoreLocation Cert:\\CurrentUser\\My -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5) -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')
try { Export-PfxCertificate -Cert $c -FilePath '${PFX_FILE.replace(/'/g, "''")}' -Password $pw -CryptoAlgorithmOption AES256_SHA256 | Out-Null }
finally { Remove-Item "Cert:\\CurrentUser\\My\\$($c.Thumbprint)" }
$sha = [Security.Cryptography.SHA256]::Create()
[Console]::Out.Write((($sha.ComputeHash($c.RawData) | ForEach-Object { $_.ToString('x2') }) -join ''))`;
  fs.mkdirSync(DIR, { recursive: true });
  const fingerprint = await runPs(script, password);
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) throw new Error('Certificate generation failed');
  await secrets.save('lan-cert', { password });
  saveConfig({ ...loadConfig(), fingerprint });
  console.log(`Phone access: generated certificate ${shortFingerprint(fingerprint)}`);
  return { pfx: fs.readFileSync(PFX_FILE), passphrase: password, fingerprint };
}

// ---------------------------------------------------------------------------
// Network helpers

function isPrivateAddress(addr) {
  const a = String(addr || '').replace(/^::ffff:/, '');
  return /^10\./.test(a) || /^192\.168\./.test(a) || /^172\.(1[6-9]|2\d|3[01])\./.test(a) ||
    /^169\.254\./.test(a) || a === '127.0.0.1' || a === '::1' || /^f[cd][0-9a-f]{2}:/i.test(a) || /^fe80:/i.test(a);
}

// Virtual adapters (VMware, VirtualBox, Hyper-V, WSL) are unreachable from a phone.
const VIRTUAL = /vmware|virtualbox|vbox|vethernet|hyper-v|wsl|docker|loopback|bluetooth/i;

function lanAddresses() {
  const out = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const i of list || []) {
      if (i.family === 'IPv4' && !i.internal && isPrivateAddress(i.address) && !/^169\.254\./.test(i.address)) {
        out.push({ address: i.address, interface: name, virtual: VIRTUAL.test(name) });
      }
    }
  }
  // Real adapters first, Wi-Fi/Ethernet before anything else, so the first address is the one to use.
  const rank = (a) => (a.virtual ? 2 : /wi-?fi|wlan|wireless|ethernet/i.test(a.interface) ? 0 : 1);
  return out.sort((a, b) => rank(a) - rank(b));
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(body));
}

function readBody(req, limit = 4096) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(new Error('invalid JSON')); } });
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// Pairing and auth

function createPairingCode() {
  pairing = { code: String(crypto.randomInt(0, 1000000)).padStart(6, '0'), expiresAt: Date.now() + PAIR_TTL_MS, attempts: 0 };
  return pairing;
}

function tryPair(code, name) {
  if (!pairing || Date.now() > pairing.expiresAt) { pairing = null; return { error: 'No active pairing code. Create one on the PC.' }; }
  pairing.attempts += 1;
  const ok = typeof code === 'string' && code.length === 6 &&
    crypto.timingSafeEqual(Buffer.from(code), Buffer.from(pairing.code));
  if (!ok) {
    if (pairing.attempts >= PAIR_MAX_ATTEMPTS) { pairing = null; return { error: 'Too many wrong codes. Create a new code on the PC.' }; }
    return { error: 'Wrong pairing code.' };
  }
  pairing = null;
  const token = crypto.randomBytes(32).toString('base64url');
  const device = {
    id: crypto.randomUUID(),
    name: String(name || 'Android phone').replace(/[^\w .()-]/g, '').slice(0, 40) || 'Android phone',
    tokenHash: sha256(token),
    pairedAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
  };
  saveDevices([...loadDevices(), device]);
  console.log(`Phone access: paired "${device.name}"`);
  return { token, device };
}

let lastSeenWrite = 0;
function authenticate(req) {
  const m = String(req.headers.authorization || '').match(/^Bearer ([\w-]{20,100})$/);
  if (!m) return null;
  const hash = Buffer.from(sha256(m[1]));
  const devices = loadDevices();
  const device = devices.find((d) => d.tokenHash.length === hash.length && crypto.timingSafeEqual(Buffer.from(d.tokenHash), hash));
  if (device && Date.now() - lastSeenWrite > 60000) {
    device.lastSeen = new Date().toISOString();
    lastSeenWrite = Date.now();
    saveDevices(devices);
  }
  return device || null;
}

// ---------------------------------------------------------------------------
// Read-only view for the phone

async function phoneState() {
  const s = await deps.buildState();
  const live = deps.getLive();
  // Drop links to localhost URLs: they would point at the phone itself.
  if (live.siem && live.siem.watches) live.siem.watches = live.siem.watches.map(({ link, ...w }) => w);
  if (live.siem && live.siem.ingestion) live.siem.ingestion = live.siem.ingestion.map(({ link, ...i }) => i);
  if (live.siem) delete live.siem.web;
  return {
    system: { hostname: s.system.hostname, totalMemMB: s.system.totalMemMB, freeMemMB: s.system.freeMemMB },
    categories: s.categories,
    tools: s.tools.map((t) => ({ id: t.id, name: t.name, category: t.category, version: t.installedVersion || t.version, installed: t.installed, running: t.running, description: t.description })),
    live,
    generatedAt: new Date().toISOString(),
  };
}

async function handle(req, res) {
  if (!isPrivateAddress(req.socket.remoteAddress)) { req.socket.destroy(); return; }
  const url = new URL(req.url, 'https://phone.local');
  try {
    if (req.method === 'POST' && url.pathname === '/m/pair') {
      const body = await readBody(req);
      const r = tryPair(String(body.code || ''), body.name);
      if (r.error) return sendJson(res, 403, { error: r.error });
      return sendJson(res, 200, { token: r.token, deviceId: r.device.id, pc: os.hostname() });
    }
    if (req.method === 'GET' && url.pathname === '/m/state') {
      const device = authenticate(req);
      if (!device) return sendJson(res, 401, { error: 'This phone is not paired, or was revoked. Pair it again.' });
      return sendJson(res, 200, await phoneState());
    }
    sendJson(res, 404, { error: 'Not found' });
  } catch (e) {
    sendJson(res, 500, { error: 'Server error' });
    console.error('Phone access error:', e.message);
  }
}

// ---------------------------------------------------------------------------
// Lifecycle and the PC-side API (called by server.js from loopback-only routes)

async function start() {
  if (server || !loadConfig().enabled) return;
  const cert = await ensureCertificate();
  server = https.createServer({ pfx: cert.pfx, passphrase: cert.passphrase, minVersion: 'TLSv1.2' }, handle);
  server.headersTimeout = 10000;
  server.requestTimeout = 30000;
  await new Promise((resolve, reject) => {
    server.once('error', (e) => { server = null; reject(e); });
    server.listen(PORT, '0.0.0.0', resolve);
  });
  console.log(`Phone access: listening on https://<this-pc>:${PORT} (read-only)`);
}

function stop() {
  if (server) { server.close(); server = null; }
  pairing = null;
}

async function setEnabled(enabled) {
  saveConfig({ ...loadConfig(), enabled: Boolean(enabled) });
  if (enabled) await start(); else stop();
}

function status() {
  const config = loadConfig();
  return {
    enabled: Boolean(config.enabled),
    listening: Boolean(server),
    port: PORT,
    addresses: lanAddresses(),
    fingerprint: config.fingerprint || null,
    fingerprintShort: shortFingerprint(config.fingerprint),
    pairing: pairing && Date.now() < pairing.expiresAt ? { active: true, expiresAt: new Date(pairing.expiresAt).toISOString() } : { active: false },
    devices: loadDevices().map(({ tokenHash, ...d }) => d),
  };
}

function newPairingCode() {
  if (!server) throw new Error('Turn on phone access first.');
  const p = createPairingCode();
  return { code: p.code, expiresAt: new Date(p.expiresAt).toISOString(), ...status() };
}

function revoke(id) {
  const devices = loadDevices();
  const next = devices.filter((d) => d.id !== id);
  if (next.length === devices.length) return false;
  saveDevices(next);
  return true;
}

function init(dependencies) {
  deps = dependencies;
  start().catch((e) => console.error('Phone access failed to start:', e.message));
}

module.exports = { init, setEnabled, status, newPairingCode, revoke, PORT };
