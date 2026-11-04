'use strict';
/*
 * Security Labs mobile (read-only view of the Security Labs Console on your PC).
 * Network calls go through window.LabBridge (native, certificate-pinned HTTPS).
 * Pairing: enter PC address -> compare the certificate fingerprint with the PC -> enter code.
 */

const DEFAULT_PORT = 7743;
const REFRESH_MS = 15000;
const view = document.getElementById('view');
const subtitle = document.getElementById('subtitle');
const refreshBtn = document.getElementById('refreshBtn');
const settingsBtn = document.getElementById('settingsBtn');

let config = loadConfig();   // { host, port, fingerprint, token, pc }
let screen = null;           // 'address' | 'verify' | 'code' | 'dashboard' | 'settings'
let draft = {};              // pairing in progress: { host, port, fingerprint }
let data = null;             // last /m/state
let lastError = null;
let timer = null;

// ---------------------------------------------------------------- helpers

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') el.style.cssText = v; // CSSOM: allowed by the page's CSP, unlike style="" attributes
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function ago(value) {
  if (!value) return 'never';
  const ms = Date.now() - (typeof value === 'number' ? value : Date.parse(value));
  if (!Number.isFinite(ms)) return '-';
  if (ms < 60000) return 'just now';
  if (ms < 3600000) return `${Math.round(ms / 60000)} min ago`;
  if (ms < 86400000) return `${Math.round(ms / 3600000)} h ago`;
  return `${Math.round(ms / 86400000)} d ago`;
}
const fmt = (n) => (n === null || n === undefined ? '-' : Number(n).toLocaleString());
const shortFp = (fp) => (fp ? fp.slice(0, 12).toUpperCase().match(/.{4}/g).join('-') : '');

let toastTimer = null;
function toast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast${isError ? ' error' : ''}`;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, isError ? 6000 : 3000);
}

// ---------------------------------------------------------------- native bridge

const pending = new Map();
let nextId = 1;
window.__labResolve = (id, json) => {
  const p = pending.get(id);
  if (!p) return;
  pending.delete(id);
  let r; try { r = JSON.parse(json); } catch { r = { status: 0, error: 'bad response' }; }
  p(r);
};

function request(method, path, { body = null, bearer = '', pin = '', host, port } = {}) {
  if (!window.LabBridge) return Promise.resolve({ status: 0, error: 'Native bridge unavailable' });
  const id = nextId++;
  const url = `https://${host}:${port}${path}`;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    window.LabBridge.request(id, method, url, body ? JSON.stringify(body) : '', bearer, pin);
  });
}

function loadConfig() {
  try { const raw = window.LabBridge && window.LabBridge.getConfig(); return raw ? JSON.parse(raw) : null; } catch { return null; }
}
function saveConfig(c) { config = c; window.LabBridge.saveConfig(JSON.stringify(c)); }
function clearConfig() { config = null; data = null; window.LabBridge.clearConfig(); }

// ---------------------------------------------------------------- navigation

function go(next) {
  screen = next;
  clearInterval(timer);
  const paired = Boolean(config);
  refreshBtn.hidden = !(paired && screen === 'dashboard');
  settingsBtn.hidden = !(paired && screen === 'dashboard');
  if (screen === 'dashboard') {
    subtitle.textContent = config ? `${config.pc || config.host} · read-only` : '';
    renderDashboard();
    refresh();
    timer = setInterval(() => { if (!document.hidden) refresh(); }, REFRESH_MS);
  } else {
    subtitle.textContent = paired ? `${config.pc || config.host}` : 'Not connected';
    ({ address: renderAddress, verify: renderVerify, code: renderCode, settings: renderSettings })[screen]();
  }
  window.scrollTo(0, 0);
}

// Hardware back button: step back inside the app before leaving it.
window.__labBack = () => {
  if (screen === 'settings') { go('dashboard'); return true; }
  if (screen === 'verify' || screen === 'code') { go('address'); return true; }
  return false;
};

refreshBtn.addEventListener('click', () => refresh(true));
settingsBtn.addEventListener('click', () => go('settings'));
document.addEventListener('visibilitychange', () => { if (!document.hidden && screen === 'dashboard') refresh(); });

// ---------------------------------------------------------------- pairing screens

function steps(n) { return h('div', { class: 'steps' }, [1, 2, 3].map((i) => h('i', { class: i <= n ? 'on' : null }))); }

function renderAddress() {
  const input = h('input', {
    class: 'input', type: 'text', inputmode: 'decimal', placeholder: '192.168.1.20', autocomplete: 'off',
    autocapitalize: 'off', spellcheck: 'false', value: draft.host ? `${draft.host}${draft.port !== DEFAULT_PORT ? ':' + draft.port : ''}` : null,
  });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Connect');
  const form = h('form', {
    class: 'card', style: 'display:grid;gap:14px',
    onsubmit: async (e) => {
      e.preventDefault();
      const m = input.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').match(/^([\w.-]+)(?::(\d{2,5}))?$/);
      if (!m) { toast('Enter the PC address shown in the console, e.g. 192.168.1.20', true); return; }
      draft = { host: m[1], port: m[2] ? Number(m[2]) : DEFAULT_PORT };
      btn.disabled = true; btn.textContent = 'Connecting...';
      // Probe without a pin to read the certificate fingerprint. Nothing secret is sent.
      const r = await request('GET', '/m/state', { host: draft.host, port: draft.port });
      btn.disabled = false; btn.textContent = 'Connect';
      if (!r.fingerprint) {
        toast(`Can't reach ${draft.host}:${draft.port}. Same Wi-Fi? Phone access turned on?`, true);
        return;
      }
      draft.fingerprint = r.fingerprint;
      go('verify');
    },
  },
  steps(1),
  h('label', { class: 'field' }, h('span', {}, 'PC address'), input),
  h('p', { class: 'muted small' }, 'On your PC, open the Security Labs Console > Connections > Phone access, turn it on and tap "Pair a phone". Enter the PC address it shows.'),
  btn);

  view.replaceChildren(
    h('div', { class: 'hero' }, h('h1', {}, 'Connect to your lab'), h('p', { class: 'muted' }, 'View your SIEM and SOAR lab from your phone. Read-only and Wi-Fi only.')),
    form);
  setTimeout(() => input.focus(), 50);
}

function renderVerify() {
  view.replaceChildren(
    h('div', { class: 'card', style: 'display:grid;gap:14px' },
      steps(2),
      h('strong', {}, 'Check the fingerprint'),
      h('p', { class: 'muted' }, `This is the security certificate of ${draft.host}. It must match the fingerprint shown on your PC under "Pair a phone".`),
      h('div', { class: 'fp' }, shortFp(draft.fingerprint)),
      h('p', { class: 'muted small' }, 'If it does not match, do not continue: something else on your network is answering.'),
      h('div', { class: 'row' },
        h('button', { class: 'btn', type: 'button', onclick: () => go('address') }, "Doesn't match"),
        h('button', { class: 'btn primary', type: 'button', onclick: () => go('code') }, 'It matches'))));
}

function renderCode() {
  const input = h('input', { class: 'input code', type: 'text', inputmode: 'numeric', maxlength: '7', placeholder: '000000', autocomplete: 'one-time-code' });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Pair');
  view.replaceChildren(h('form', {
    class: 'card', style: 'display:grid;gap:14px',
    onsubmit: async (e) => {
      e.preventDefault();
      const code = input.value.replace(/\D/g, '');
      if (code.length !== 6) { toast('Enter the 6-digit code from your PC.', true); return; }
      btn.disabled = true; btn.textContent = 'Pairing...';
      // From here on the certificate is pinned: the code only goes to the verified PC.
      const r = await request('POST', '/m/pair', {
        host: draft.host, port: draft.port, pin: draft.fingerprint,
        body: { code, name: window.LabBridge.deviceName() },
      });
      btn.disabled = false; btn.textContent = 'Pair';
      let out = {}; try { out = JSON.parse(r.body || '{}'); } catch { /* ignore */ }
      if (r.pinMismatch) { toast('The PC certificate changed during pairing. Start again.', true); go('address'); return; }
      if (r.status !== 200 || !out.token) { toast(out.error || r.error || 'Pairing failed', true); input.value = ''; return; }
      saveConfig({ host: draft.host, port: draft.port, fingerprint: draft.fingerprint, token: out.token, pc: out.pc, pairedAt: new Date().toISOString() });
      draft = {};
      toast(`Paired with ${out.pc}`);
      go('dashboard');
    },
  },
  steps(3),
  h('strong', {}, 'Enter the pairing code'),
  h('p', { class: 'muted' }, 'The 6-digit code shown on your PC. It works once and expires after 5 minutes.'),
  input, btn));
  setTimeout(() => input.focus(), 50);
}

// ---------------------------------------------------------------- dashboard

async function refresh(manual = false) {
  if (!config) return;
  refreshBtn.classList.add('spinning');
  const r = await request('GET', '/m/state', { host: config.host, port: config.port, pin: config.fingerprint, bearer: config.token });
  refreshBtn.classList.remove('spinning');
  if (screen !== 'dashboard') return;

  if (r.status === 200) {
    try { data = JSON.parse(r.body); lastError = null; } catch { lastError = 'Unreadable response from the PC.'; }
    if (manual) toast('Updated');
  } else if (r.status === 401) {
    clearConfig();
    toast('This phone was removed on the PC. Pair it again.', true);
    go('address');
    return;
  } else if (r.pinMismatch) {
    lastError = 'Security warning: the PC presented a different certificate than the one this phone trusts. Not connecting. If you reset phone access on the PC, unpair and pair again.';
  } else {
    lastError = `Can't reach ${config.pc || config.host}. Make sure you're on the same Wi-Fi and the console is running.`;
  }
  renderDashboard();
}

function statePill(src) {
  const s = (src && src.state) || 'loading';
  const map = { connected: ['ok', 'Connected'], 'needs-credentials': ['warn', 'Needs setup on PC'], offline: ['', 'Not running'], error: ['warn', 'Error'], loading: ['', '...'] };
  const [cls, label] = map[s] || map.loading;
  return h('span', { class: `pill ${cls}` }, label);
}

function liveCard(title, src, lines) {
  return h('div', { class: 'card live' },
    h('div', { class: 'live-head' }, h('strong', {}, title), statePill(src)),
    lines.filter(Boolean).map((l, i) => h('div', { class: i === 0 ? 'live-main' : 'live-sub' }, l)));
}

function toolStatus(t) {
  if (!t.installed) return ['missing', 'Not installed'];
  if (t.running === true) return ['running', 'Running'];
  if (t.running === false) return ['ready', 'Stopped'];
  return ['ready', 'Installed'];
}

function renderDashboard() {
  const parts = [];
  if (lastError) parts.push(h('div', { class: 'banner' }, lastError));
  if (!data) {
    parts.push(h('div', { class: 'card muted' }, lastError ? 'No data yet.' : 'Loading your lab...'));
    view.replaceChildren(...parts);
    return;
  }

  const { live = {}, system, tools, categories } = data;
  const s = live.siem || {}; const r = live.suricata || {}; const n = live.n8n || {};
  const events = s.ingestion ? s.ingestion.reduce((a, b) => a + b.count24h, 0) : null;
  const hits = s.watches ? s.watches.filter((w) => w.count > 0) : [];

  parts.push(h('p', { class: 'muted small' }, `Updated ${ago(data.generatedAt)} · refreshes every 15 s`));
  parts.push(h('div', { class: 'cards' },
    liveCard('Elastic SIEM', s, s.state === 'connected' ? [`${fmt(events)} events`, `last 24 h · ${s.health}`] : [s.message]),
    liveCard('Watchlist', s, s.state === 'connected' ? [hits.length ? `${hits.length} triggered` : 'All quiet', 'last 24 h'] : ['Needs Elastic']),
    liveCard('Suricata', r, r.state === 'connected' ? [`${r.alerts.length} alerts`, `last event ${ago(r.lastEvent)}`] : [r.message]),
    liveCard('n8n', n, n.state === 'connected' ? [`${n.workflows.filter((w) => w.active).length} active`, `${n.workflows.length} workflows`] : [n.message])));

  if (s.state === 'connected') {
    parts.push(h('h2', {}, 'Watchlist (24 h)'));
    parts.push(h('div', { class: 'list' }, s.watches.map((w) => h('div', { class: `card item${w.count > 0 ? ' hit' : ''}` },
      h('div', { class: 'item-top' }, h('span', {}, h('span', { class: `sev ${w.severity}` }, w.severity), ' ', w.title), h('span', { class: 'count' }, w.count === null ? '!' : fmt(w.count))),
      h('span', { class: 'muted small' }, [w.attack, w.count > 0 ? `last ${ago(w.last)}` : null].filter(Boolean).join(' · ') || ' ')))));
  }

  if (r.state === 'connected' && r.alerts.length) {
    parts.push(h('h2', {}, 'Latest IDS alerts'));
    parts.push(h('div', { class: 'list' }, r.alerts.slice(0, 15).map((a) => h('div', { class: 'card item' },
      h('div', { class: 'item-top' }, h('strong', {}, a.signature), h('span', { class: `sev s${a.severity}` }, `sev ${a.severity}`)),
      h('span', { class: 'muted small mono' }, `${a.src} → ${a.dest}`),
      h('span', { class: 'muted small' }, `${a.category || ''} · ${ago(a.time)}`)))));
  }

  if (n.state === 'connected' && n.executions.length) {
    parts.push(h('h2', {}, 'Recent playbook runs'));
    parts.push(h('div', { class: 'card list' }, n.executions.slice(0, 8).map((e) => h('div', { class: 'item-top' },
      h('span', {}, e.workflow), h('span', { class: `pill ${e.status === 'success' ? 'ok' : e.status === 'error' ? 'warn' : ''}` }, e.status)))));
  }

  const used = system.totalMemMB - system.freeMemMB;
  const pct = Math.round((used / system.totalMemMB) * 100);
  parts.push(h('h2', {}, 'PC memory'));
  parts.push(h('div', { class: 'card' },
    h('div', { class: 'item-top' }, h('span', {}, system.hostname), h('strong', {}, `${(used / 1024).toFixed(1)} / ${(system.totalMemMB / 1024).toFixed(1)} GB`)),
    h('div', { class: 'mem' }, h('div', { class: pct >= 90 ? 'critical' : pct >= 75 ? 'high' : null, style: `width:${pct}%` }))));

  for (const cat of categories) {
    const list = tools.filter((t) => t.category === cat.id);
    if (!list.length) continue;
    parts.push(h('h2', {}, cat.label));
    parts.push(h('div', { class: 'card tools', style: 'padding:6px 0' }, list.map((t) => {
      const [cls, label] = toolStatus(t);
      return h('div', { class: 'tool' }, h('i', { class: `dot ${cls}` }), h('span', { class: 'tool-name' }, t.name), h('span', { class: 'tool-state' }, label));
    })));
  }
  parts.push(h('p', { class: 'muted small', style: 'text-align:center;margin-top:6px' }, 'Read-only. Start and stop tools from the console on your PC.'));
  view.replaceChildren(...parts);
}

// ---------------------------------------------------------------- settings

function renderSettings() {
  view.replaceChildren(
    h('div', { class: 'card' }, h('dl', { class: 'kv' },
      h('dt', {}, 'PC'), h('dd', {}, config.pc || '-'),
      h('dt', {}, 'Address'), h('dd', { class: 'mono' }, `${config.host}:${config.port}`),
      h('dt', {}, 'Certificate'), h('dd', { class: 'mono' }, shortFp(config.fingerprint)),
      h('dt', {}, 'Paired'), h('dd', {}, ago(config.pairedAt)),
      h('dt', {}, 'Access'), h('dd', {}, 'Read-only'),
      h('dt', {}, 'App version'), h('dd', {}, window.LabBridge.appVersion()))),
    h('button', { class: 'btn', type: 'button', onclick: () => go('dashboard') }, 'Back to dashboard'),
    h('button', {
      class: 'btn danger', type: 'button',
      onclick: () => { clearConfig(); toast('Unpaired. Also revoke this phone on the PC to remove its access there.'); go('address'); },
    }, 'Unpair this phone'));
}

// ---------------------------------------------------------------- start

go(config ? 'dashboard' : 'address');
