'use strict';
/**
 * Live data connectors for the console. Each source is refreshed in the background on its own
 * interval and cached, so page polls are instant and the lab tools are not hammered:
 *
 *   siem     - Elastic: Elasticsearch REST API on 127.0.0.1:9200 (health, events per log source,
 *              24h watchlist counts) and a Kibana reachability check on 127.0.0.1:5601
 *   suricata - tail of eve.json: latest IDS alerts
 *   n8n      - REST API on 127.0.0.1:5678: health, workflows, recent executions
 *
 * Every connector reports a state: connected | needs-credentials | offline | error | loading.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const secrets = require('./secrets');

const ES = { host: '127.0.0.1', port: 9200 };
const KIBANA = { host: '127.0.0.1', port: 5601, web: 'http://localhost:5601' };
const N8N = { host: '127.0.0.1', port: 5678, web: 'http://localhost:5678' };
const EVE_FILE = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Suricata', 'log', 'eve.json');
const WATCHES_FILE = path.join(__dirname, 'watches.json');
const EVENT_INDICES = 'winlogbeat-*,filebeat-*';

// Log sources shown under "Ingestion" (Winlogbeat channels + Filebeat Suricata module).
const SOURCES = [
  { source: 'security',   label: 'Windows Security',  kql: 'winlog.channel : "Security"',
    query: { term: { 'winlog.channel': 'Security' } } },
  { source: 'system',     label: 'Windows System',    kql: 'winlog.channel : "System"',
    query: { term: { 'winlog.channel': 'System' } } },
  { source: 'sysmon',     label: 'Sysmon',            kql: 'winlog.channel : "Microsoft-Windows-Sysmon/Operational"',
    query: { term: { 'winlog.channel': 'Microsoft-Windows-Sysmon/Operational' } } },
  { source: 'powershell', label: 'PowerShell',        kql: 'winlog.channel : ("Microsoft-Windows-PowerShell/Operational" or "Windows PowerShell")',
    query: { terms: { 'winlog.channel': ['Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell'] } } },
  { source: 'defender',   label: 'Defender',          kql: 'winlog.channel : "Microsoft-Windows-Windows Defender/Operational"',
    query: { term: { 'winlog.channel': 'Microsoft-Windows-Windows Defender/Operational' } } },
  { source: 'suricata',   label: 'Suricata IDS',      kql: 'event.module : "suricata"',
    query: { term: { 'event.module': 'suricata' } } },
];

const TTL = { siem: 30000, suricata: 10000, n8n: 20000 };
const cache = {
  siem: { at: 0, busy: null, data: { state: 'loading' } },
  suricata: { at: 0, busy: null, data: { state: 'loading' } },
  n8n: { at: 0, busy: null, data: { state: 'loading' } },
};

// ---------------------------------------------------------------------------
// HTTP helper (loopback only, plain HTTP: these services listen on 127.0.0.1)

function request({ host, port, method = 'GET', pathname, headers = {}, body = null, timeout = 15000 }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, method, path: pathname, headers, timeout }, (res) => {
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
// Elastic (Elasticsearch + Kibana)

const basic = (creds) => 'Basic ' + Buffer.from(`${creds.username}:${creds.password}`, 'utf8').toString('base64');

async function es(creds, method, pathname, payload = null, timeout = 30000) {
  const body = payload ? JSON.stringify(payload) : null;
  const r = await request({
    ...ES, method, pathname, timeout, body,
    headers: { Authorization: basic(creds), ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}) },
  });
  if (r.status === 401) throw Object.assign(new Error('Elasticsearch rejected the saved login'), { auth: true });
  if (r.status >= 400) {
    let reason = `HTTP ${r.status}`;
    try { reason = JSON.parse(r.body).error.reason || reason; } catch { /* keep status */ }
    throw new Error(`Elasticsearch: ${reason}`);
  }
  return JSON.parse(r.body);
}

/** Checks a username/password against Elasticsearch without storing it. Returns the version. */
async function testElastic(creds) {
  const info = await es(creds, 'GET', '/');
  return info.version.number;
}

function loadWatches() {
  try { return JSON.parse(fs.readFileSync(WATCHES_FILE, 'utf8')).watches || []; } catch { return []; }
}

/** Kibana Discover link for a KQL query over the last 24 hours (rison-encoded app state). */
function discoverLink(kql, from = 'now-24h') {
  const rison = (s) => `'${String(s).replace(/!/g, '!!').replace(/'/g, "!'")}'`;
  const a = `(query:(language:kuery,query:${rison(kql)}))`;
  const g = `(time:(from:${from},to:now))`;
  return `${KIBANA.web}/app/discover#/?_g=${encodeURIComponent(g)}&_a=${encodeURIComponent(a)}`;
}

async function kibanaUp() {
  try { const r = await request({ ...KIBANA, pathname: '/api/status', timeout: 4000 }); return r.status === 200 || r.status === 401; } catch { return false; }
}

async function refreshSiem() {
  // Reachability first, so a stopped Elasticsearch reads "Not running" rather than "Needs connection".
  try {
    await request({ ...ES, pathname: '/', timeout: 5000 });
  } catch {
    return { state: 'offline', name: 'Elastic', message: 'Elasticsearch is not running. Start it from its page in the console.' };
  }

  let creds;
  try { creds = await secrets.load('elastic'); } catch (e) { return { state: 'error', name: 'Elastic', message: e.message }; }
  if (!creds) return { state: 'needs-credentials', name: 'Elastic', message: 'Elasticsearch is running. Add the elastic login under Connections.' };

  try {
    const [info, health, kibana] = await Promise.all([
      es(creds, 'GET', '/'),
      es(creds, 'GET', '/_cluster/health'),
      kibanaUp(),
    ]);
    const search = `/${EVENT_INDICES}/_search?ignore_unavailable=true&allow_no_indices=true&request_cache=false`;
    const last24h = { range: { '@timestamp': { gte: 'now-24h' } } };

    // Ingestion: one request for every source.
    const ing = await es(creds, 'POST', search, {
      size: 0, track_total_hits: true, query: last24h,
      aggs: {
        sources: {
          filters: { filters: Object.fromEntries(SOURCES.map((s) => [s.source, s.query])) },
          aggs: {
            last: { max: { field: '@timestamp' } },
            recent: { filter: { range: { '@timestamp': { gte: 'now-15m' } } } },
          },
        },
      },
    });
    const buckets = (ing.aggregations && ing.aggregations.sources.buckets) || {};
    const ingestion = SOURCES.map((s) => {
      const b = buckets[s.source] || {};
      return {
        source: s.source, label: s.label,
        count24h: b.doc_count || 0,
        count15m: (b.recent && b.recent.doc_count) || 0,
        lastEvent: b.last && b.last.value ? b.last.value : null,
        link: discoverLink(s.kql, 'now-15m'),
      };
    });

    // Watchlist: one request for every watch.
    const watchDefs = loadWatches();
    const wr = await es(creds, 'POST', search, {
      size: 0, query: last24h,
      aggs: {
        watches: {
          filters: { filters: Object.fromEntries(watchDefs.map((w) => [w.id, w.query])) },
          aggs: { last: { max: { field: '@timestamp' } } },
        },
      },
    });
    const wb = (wr.aggregations && wr.aggregations.watches.buckets) || {};
    const watches = watchDefs.map(({ query, ...w }) => {
      const b = wb[w.id] || {};
      return { ...w, count: b.doc_count || 0, last: b.last && b.last.value ? b.last.value : null, link: discoverLink(w.kql) };
    });

    return {
      state: 'connected', name: 'Elastic',
      version: info.version.number,
      health: health.status,
      kibana,
      ingestion, watches,
      web: KIBANA.web,
    };
  } catch (e) {
    if (e.auth) return { state: 'needs-credentials', name: 'Elastic', message: 'Elasticsearch rejected the saved login. Update it under Connections.' };
    if (offline(e)) return { state: 'offline', name: 'Elastic', message: 'Elasticsearch is not running.' };
    return { state: 'error', name: 'Elastic', message: e.message };
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

const refreshers = { siem: refreshSiem, suricata: refreshSuricata, n8n: refreshN8n };

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
  const key = source === 'elastic' ? 'siem' : source;
  if (cache[key]) { cache[key].at = 0; refresh(key, true); }
}

module.exports = { getLive, invalidate, testElastic, testN8n, SOURCES };
