'use strict';
/**
 * Live data connectors for the console. Each source is refreshed in the background on its own
 * interval and cached, so page polls are instant and the lab tools are not hammered:
 *
 *   splunk   - REST API on 127.0.0.1:8089: health, events per index, 24h watchlist counts
 *   suricata - tail of eve.json: latest IDS alerts
 *   n8n      - REST API on 127.0.0.1:5678: health, workflows, recent executions
 *
 * Every connector reports a state: connected | needs-credentials | offline | error | loading.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const secrets = require('./secrets');

const SPLUNK = { host: '127.0.0.1', port: 8089, web: 'http://localhost:8000' };
const N8N = { host: '127.0.0.1', port: 5678, web: 'http://localhost:5678' };
const EVE_FILE = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Suricata', 'log', 'eve.json');
const WATCHES_FILE = path.join(__dirname, 'watches.json');
const INDEXES = ['wineventlog', 'sysmon', 'powershell', 'defender', 'suricata'];

const TTL = { splunk: 90000, suricata: 10000, n8n: 20000 };
const cache = {
  splunk: { at: 0, busy: null, data: { state: 'loading' } },
  suricata: { at: 0, busy: null, data: { state: 'loading' } },
  n8n: { at: 0, busy: null, data: { state: 'loading' } },
};

// ---------------------------------------------------------------------------
// HTTP helper (loopback only)

function request({ secure, host, port, method = 'GET', pathname, headers = {}, body = null, timeout = 15000 }) {
  return new Promise((resolve, reject) => {
    const lib = secure ? https : http;
    const req = lib.request({
      host, port, method, path: pathname, headers, timeout,
      // Lab services on 127.0.0.1 use self-signed certificates (Splunk management port).
      ...(secure ? { rejectUnauthorized: false } : {}),
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const offline = (err) => ['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH'].includes(err.code) || /timed out/.test(err.message);

// ---------------------------------------------------------------------------
// Splunk

function splunkAuth(creds) {
  return 'Basic ' + Buffer.from(`${creds.username}:${creds.password}`, 'utf8').toString('base64');
}

async function splunkGet(creds, pathname) {
  const r = await request({ secure: true, ...SPLUNK, pathname, headers: { Authorization: splunkAuth(creds) } });
  if (r.status === 401) throw Object.assign(new Error('Splunk rejected the saved login'), { auth: true });
  if (r.status >= 400) throw new Error(`Splunk returned HTTP ${r.status}`);
  return JSON.parse(r.body);
}

/** Runs a search to completion (export endpoint) and returns result rows. */
async function splunkSearch(creds, spl, timeout = 90000) {
  const body = new URLSearchParams({ search: spl, output_mode: 'json' }).toString();
  const r = await request({
    secure: true, ...SPLUNK, method: 'POST', pathname: '/services/search/jobs/export', timeout, body,
    headers: { Authorization: splunkAuth(creds), 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
  });
  if (r.status === 401) throw Object.assign(new Error('Splunk rejected the saved login'), { auth: true });
  if (r.status >= 400) throw new Error(`Splunk search failed (HTTP ${r.status})`);
  return r.body.split('\n').filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch { return null; }
  }).filter((o) => o && o.result && o.preview === false).map((o) => o.result);
}

/** Checks a username/password against Splunk without storing it. */
async function testSplunk(creds) {
  const info = await splunkGet(creds, '/services/server/info?output_mode=json');
  return info.entry[0].content.version;
}

function loadWatches() {
  try { return JSON.parse(fs.readFileSync(WATCHES_FILE, 'utf8')).watches || []; } catch { return []; }
}

const splunkLink = (spl, earliest = '-24h') =>
  `${SPLUNK.web}/en-US/app/search/search?${new URLSearchParams({ q: `search ${spl}`, earliest, latest: 'now' })}`;

async function refreshSplunk() {
  // Reachability first, so a stopped Splunk reads "Not running" rather than "Needs connection".
  try {
    await request({ secure: true, ...SPLUNK, pathname: '/services/server/info', timeout: 5000 });
  } catch (e) {
    return { state: 'offline', message: 'Splunk is not running. Start it from the Splunk page.' };
  }

  let creds;
  try { creds = await secrets.load('splunk'); } catch (e) { return { state: 'error', message: e.message }; }
  if (!creds) return { state: 'needs-credentials', message: 'Splunk is running. Add your Splunk login under Connections.' };

  try {
    const [info, health] = await Promise.all([
      splunkGet(creds, '/services/server/info?output_mode=json'),
      splunkGet(creds, '/services/server/health/splunkd?output_mode=json').catch(() => null),
    ]);
    const content = info.entry[0].content;

    const list = INDEXES.join(',');
    const ingestionRows = await splunkSearch(creds,
      `| tstats count max(_time) as last where index IN (${list}) earliest=-24h by index ` +
      `| append [| tstats count as recent where index IN (${list}) earliest=-15m by index] ` +
      '| stats sum(count) as count sum(recent) as recent max(last) as last by index');
    const byIndex = new Map(ingestionRows.map((r) => [r.index, r]));
    const ingestion = INDEXES.map((index) => {
      const r = byIndex.get(index) || {};
      return {
        index,
        count24h: Number(r.count || 0),
        count15m: Number(r.recent || 0),
        lastEvent: r.last ? Number(r.last) * 1000 : null,
        link: splunkLink(`index=${index}`, '-15m'),
      };
    });

    // Watchlist: run sequentially to keep load low on an 8 GB machine.
    const watches = [];
    for (const w of loadWatches()) {
      try {
        const rows = await splunkSearch(creds, `search ${w.spl} earliest=-24h | stats count max(_time) as last`);
        const row = rows[0] || {};
        watches.push({ ...w, count: Number(row.count || 0), last: row.last ? Number(row.last) * 1000 : null, link: splunkLink(w.spl) });
      } catch (e) {
        if (e.auth) throw e;
        watches.push({ ...w, count: null, error: e.message, link: splunkLink(w.spl) });
      }
    }

    return {
      state: 'connected',
      version: content.version,
      license: content.activeLicenseGroup,
      health: health ? health.entry[0].content.health : 'unknown',
      ingestion,
      watches,
      web: SPLUNK.web,
    };
  } catch (e) {
    if (e.auth) return { state: 'needs-credentials', message: 'Splunk rejected the saved login. Update it under Connections.' };
    if (offline(e)) return { state: 'offline', message: 'Splunk is not running.' };
    return { state: 'error', message: e.message };
  }
}

// ---------------------------------------------------------------------------
// Suricata (eve.json tail)

function readTail(file, bytes) {
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const start = Math.max(0, size - bytes);
    const buf = Buffer.alloc(size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    let text = buf.toString('utf8');
    if (start > 0) text = text.slice(text.indexOf('\n') + 1); // drop partial first line
    return { text, size };
  } finally { fs.closeSync(fd); }
}

async function refreshSuricata() {
  if (!fs.existsSync(EVE_FILE)) {
    return { state: 'offline', message: 'No eve.json yet. Start Suricata from the console to begin capturing.' };
  }
  try {
    const { text, size } = readTail(EVE_FILE, 2 * 1024 * 1024);
    const events = text.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const types = {};
    for (const e of events) types[e.event_type] = (types[e.event_type] || 0) + 1;
    const alerts = events.filter((e) => e.event_type === 'alert').slice(-25).reverse().map((e) => ({
      time: e.timestamp,
      signature: e.alert && e.alert.signature,
      category: e.alert && e.alert.category,
      severity: e.alert && e.alert.severity,
      sid: e.alert && e.alert.signature_id,
      src: `${e.src_ip}${e.src_port ? ':' + e.src_port : ''}`,
      dest: `${e.dest_ip}${e.dest_port ? ':' + e.dest_port : ''}`,
      proto: e.proto,
    }));
    const lastEvent = events.length ? events[events.length - 1].timestamp : null;
    return { state: 'connected', fileSizeMB: +(size / 1048576).toFixed(1), sampled: events.length, types, alerts, lastEvent };
  } catch (e) {
    return { state: 'error', message: `Cannot read eve.json: ${e.message}` };
  }
}

// ---------------------------------------------------------------------------
// n8n

async function n8nGet(apiKey, pathname) {
  const r = await request({ ...N8N, pathname, headers: { 'X-N8N-API-KEY': apiKey, Accept: 'application/json' } });
  if (r.status === 401 || r.status === 403) throw Object.assign(new Error('n8n rejected the saved API key'), { auth: true });
  if (r.status >= 400) throw new Error(`n8n returned HTTP ${r.status}`);
  return JSON.parse(r.body);
}

async function testN8n(apiKey) {
  await n8nGet(apiKey, '/api/v1/workflows?limit=1');
}

async function refreshN8n() {
  try {
    const health = await request({ ...N8N, pathname: '/healthz', timeout: 4000 });
    if (health.status >= 400) return { state: 'error', message: `n8n health check returned HTTP ${health.status}` };
  } catch (e) {
    return { state: 'offline', message: 'n8n is not running. Start it from the console.' };
  }

  let creds;
  try { creds = await secrets.load('n8n'); } catch (e) { return { state: 'error', message: e.message }; }
  if (!creds) return { state: 'needs-credentials', healthy: true, message: 'n8n is running. Add an API key under Connections to see workflows.', web: N8N.web };

  try {
    const [wf, ex] = await Promise.all([
      n8nGet(creds.apiKey, '/api/v1/workflows?limit=100'),
      n8nGet(creds.apiKey, '/api/v1/executions?limit=10'),
    ]);
    const workflows = (wf.data || []).map((w) => ({ id: w.id, name: w.name, active: Boolean(w.active), updatedAt: w.updatedAt }));
    const names = new Map(workflows.map((w) => [String(w.id), w.name]));
    const executions = (ex.data || []).map((e) => ({
      id: e.id, workflow: names.get(String(e.workflowId)) || `Workflow ${e.workflowId}`,
      status: e.status || (e.finished ? 'success' : 'running'), mode: e.mode,
      startedAt: e.startedAt, stoppedAt: e.stoppedAt,
    }));
    return { state: 'connected', healthy: true, workflows, executions, web: N8N.web };
  } catch (e) {
    if (e.auth) return { state: 'needs-credentials', healthy: true, message: 'n8n rejected the saved API key. Update it under Connections.', web: N8N.web };
    return { state: 'error', message: e.message };
  }
}

// ---------------------------------------------------------------------------
// Cache and public API

const refreshers = { splunk: refreshSplunk, suricata: refreshSuricata, n8n: refreshN8n };

function refresh(source, force = false) {
  const c = cache[source];
  if (c.busy) return c.busy;
  if (!force && Date.now() - c.at < TTL[source]) return Promise.resolve(c.data);
  c.busy = refreshers[source]().catch((e) => ({ state: 'error', message: e.message })).then((data) => {
    c.data = { ...data, updatedAt: new Date().toISOString() };
    c.at = Date.now();
    c.busy = null;
    return c.data;
  });
  return c.busy;
}

/** Returns cached live data immediately and refreshes stale sources in the background. */
function getLive() {
  for (const s of Object.keys(cache)) refresh(s);
  return Object.fromEntries(Object.entries(cache).map(([k, v]) => [k, { ...v.data, refreshing: Boolean(v.busy) }]));
}

function invalidate(source) {
  if (cache[source]) cache[source].at = 0;
  refresh(source, true);
}

module.exports = { getLive, invalidate, testSplunk, testN8n };
