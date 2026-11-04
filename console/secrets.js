'use strict';
/**
 * Connection secrets (Elastic login, n8n API key), encrypted with Windows DPAPI for the current
 * Windows user (ConvertFrom-SecureString). Only this Windows account on this machine can decrypt
 * them. Stored at %LOCALAPPDATA%\SecurityLabs\console\secrets.json, outside the repo.
 *
 * Secrets travel to PowerShell on stdin (never on a command line) as base64 UTF-8, so any
 * character survives the console code page. Decrypted values live only in this process's memory
 * and are never sent to the browser.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

const DIR = path.join(process.env.LOCALAPPDATA || os.homedir(), 'SecurityLabs', 'console');
const FILE = path.join(DIR, 'secrets.json');
const memory = new Map(); // id -> decrypted object

function runPs(script, input) {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { windowsHide: true });
    let out = '';
    let err = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('DPAPI helper timed out')); }, 60000);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(out.trim());
      else reject(new Error(`DPAPI helper failed: ${err.trim().split(/\r?\n/)[0] || code}`));
    });
    child.stdin.end(input);
  });
}

const PROTECT = `$ErrorActionPreference = 'Stop'
$plain = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()))
[Console]::Out.Write((ConvertTo-SecureString $plain -AsPlainText -Force | ConvertFrom-SecureString))`;

const UNPROTECT = `$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString ([Console]::In.ReadToEnd().Trim())
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain)))`;

function readFile() {
  try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { return {}; }
}

function writeFile(data) {
  fs.mkdirSync(DIR, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(data, null, 2), { encoding: 'utf8', mode: 0o600 });
}

/** Encrypts and stores a connection's secret object, e.g. { username, password }. */
async function save(id, value) {
  const blob = await runPs(PROTECT, Buffer.from(JSON.stringify(value), 'utf8').toString('base64'));
  const data = readFile();
  data[id] = { blob, savedAt: new Date().toISOString() };
  writeFile(data);
  memory.set(id, value);
}

/** Returns the decrypted secret object, or null if none is stored. */
async function load(id) {
  if (memory.has(id)) return memory.get(id);
  const entry = readFile()[id];
  if (!entry) return null;
  const b64 = await runPs(UNPROTECT, entry.blob);
  const value = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  memory.set(id, value);
  return value;
}

function remove(id) {
  const data = readFile();
  delete data[id];
  writeFile(data);
  memory.delete(id);
}

/** Which connections have a stored secret (no secret values). */
function summary() {
  const data = readFile();
  return Object.fromEntries(Object.entries(data).map(([id, e]) => [id, { configured: true, savedAt: e.savedAt }]));
}

module.exports = { save, load, remove, summary, FILE };
