'use strict';
/* Security Labs Console - client. Builds all DOM with createElement/textContent (no innerHTML). */

const TOKEN = document.querySelector('meta[name="console-token"]').content;
const POLL_MS = 5000;
const app = document.getElementById('app');
const nav = document.getElementById('toolNav');
const main = document.getElementById('main');
const filterInput = document.getElementById('filter');
const toggle = document.getElementById('paneToggle');

const LIVE_POLL_MS = 15000;

let state = null;
let liveData = null;     // /api/live
let connections = null;  // /api/connections
let phone = null;        // /api/phone
let pairCode = null;     // { code, expiresAt } shown after "Pair a phone"
let selected = null;     // tool id, 'connections', or null for overview
let lastRenderedKey = '';

// ---------------------------------------------------------------- helpers

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const store = {
  get(key, fallback) { try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); } catch { return fallback; } },
  set(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ } },
};

function statusOf(tool) {
  if (!tool.installed) return { cls: 'missing', label: 'Not installed' };
  if (tool.running === true) return { cls: 'running', label: 'Running' };
  if (tool.running === false) return { cls: 'ready', label: 'Installed, stopped' };
  return { cls: 'ready', label: 'Installed' };
}

function initials(name) {
  const words = name.replace(/[^A-Za-z0-9 ]/g, ' ').split(/\s+/).filter(Boolean);
  if (words.length >= 2 && !/^(the|lab)$/i.test(words[0])) return (words[0][0] + words[1][0]).toUpperCase();
  return name.replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase();
}

function toast(message, isError = false) {
  const el = h('div', { class: `toast${isError ? ' error' : ''}` }, message);
  document.getElementById('toasts').append(el);
  setTimeout(() => el.remove(), isError ? 7000 : 3500);
}

// ---------------------------------------------------------------- pane

function setCollapsed(collapsed, persist = true) {
  app.classList.toggle('collapsed', collapsed);
  toggle.setAttribute('aria-expanded', String(!collapsed));
  toggle.title = collapsed ? 'Expand tools pane ( [ )' : 'Collapse tools pane ( [ )';
  if (persist) store.set('pane-collapsed', collapsed);
}

toggle.addEventListener('click', () => setCollapsed(!app.classList.contains('collapsed')));
document.addEventListener('keydown', (e) => {
  if (e.key === '[' && !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) {
    e.preventDefault();
    setCollapsed(!app.classList.contains('collapsed'));
  }
});
const narrow = window.matchMedia('(max-width: 720px)').matches;
setCollapsed(narrow ? true : store.get('pane-collapsed', false), false);

filterInput.addEventListener('input', () => renderNav());

function renderNav() {
  if (!state) return;
  const q = filterInput.value.trim().toLowerCase();
  const frag = document.createDocumentFragment();
  for (const cat of state.categories) {
    const tools = state.tools.filter((t) => t.category === cat.id &&
      (!q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q)));
    if (!tools.length) continue;
    frag.append(h('div', { class: 'cat-label' }, cat.label));
    for (const t of tools) {
      const s = statusOf(t);
      frag.append(h('div', { class: `tool-row${selected === t.id ? ' current' : ''}` },
        h('button', {
          class: 'tool-link', type: 'button', title: `${t.name} - ${s.label}`,
          'aria-current': selected === t.id ? 'true' : null,
          onclick: () => select(t.id),
        },
        h('span', { class: 'tool-badge', 'aria-hidden': 'true' }, initials(t.name), h('i', { class: `dot ${s.cls}` })),
        h('span', { class: 'tool-name' }, t.name)),
        t.canStop ? h('button', {
          class: 'stop-mini', type: 'button', title: `Stop ${t.name}`, 'aria-label': `Stop ${t.name}`,
          onclick: (e) => stopTool(t, e.currentTarget),
        }, stopIcon()) : null));
    }
  }
  nav.replaceChildren(frag);
}

function renderMemory() {
  const { totalMemMB, freeMemMB } = state.system;
  const used = totalMemMB - freeMemMB;
  const pct = Math.round((used / totalMemMB) * 100);
  const fill = document.getElementById('memFill');
  fill.style.width = `${pct}%`;
  fill.className = `mem-fill${pct >= 90 ? ' critical' : pct >= 75 ? ' high' : ''}`;
  document.getElementById('memText').textContent = `${(used / 1024).toFixed(1)} / ${(totalMemMB / 1024).toFixed(1)} GB`;
  document.getElementById('mem').title = `Memory in use: ${pct}%`;
}

// ---------------------------------------------------------------- main views

function select(id) {
  selected = id;
  history.replaceState(null, '', id === 'connections' ? '#connections' : id ? `#tool/${id}` : '#');
  if (window.matchMedia('(max-width: 720px)').matches) setCollapsed(true, false);
  renderNav();
  renderMain(true);
  main.focus({ preventScroll: true });
}

document.getElementById('homeLink').addEventListener('click', (e) => { e.preventDefault(); select(null); });
document.getElementById('connLink').addEventListener('click', (e) => { e.preventDefault(); select('connections'); });

function renderMain(force = false) {
  if (!state) return;
  if (selected === 'connections') {
    // Only re-render on real changes so typing in the forms is never interrupted by polling.
    const key = 'conn:' + JSON.stringify([connections, phone, pairCode]);
    if (!force && key === lastRenderedKey) return;
    lastRenderedKey = key;
    main.replaceChildren(connectionsView());
    return;
  }
  const tool = selected && state.tools.find((t) => t.id === selected);
  // Avoid re-rendering (and losing text selection) when nothing visible changed.
  const liveKey = liveData ? JSON.stringify(liveData, (k, v) => (k === 'updatedAt' || k === 'refreshing' ? undefined : v)) : '';
  const key = JSON.stringify(tool || state.tools.map((t) => [t.id, t.installed, t.running])) + liveKey;
  if (!force && key === lastRenderedKey) return;
  lastRenderedKey = key;
  main.replaceChildren(tool ? toolView(tool) : overview());
}

function overview() {
  const tools = state.tools;
  const installed = tools.filter((t) => t.installed).length;
  const running = tools.filter((t) => t.running === true).length;
  const freeGB = (state.system.freeMemMB / 1024).toFixed(1);

  return h('div', { class: 'main-inner' },
    h('div', { class: 'crumb' }, state.system.hostname),
    h('h1', {}, 'Security Labs Console'),
    h('p', { class: 'lead' }, 'Every SIEM and SOAR lab tool in one place. Choose a tool in the left pane to see its status, start or stop it, and copy example commands.'),
    h('div', { class: 'stats' },
      stat(`${installed}/${tools.length}`, 'tools installed'),
      stat(String(running), 'services running'),
      stat(`${freeGB} GB`, 'memory free')),
    liveOverview(),
    h('h2', {}, 'Tools by area'),
    h('div', { class: 'cat-grid' }, state.categories.map((cat) => {
      const list = tools.filter((t) => t.category === cat.id);
      if (!list.length) return null;
      return h('div', { class: 'card cat-card' },
        h('h3', {}, cat.label),
        h('ul', {}, list.map((t) => h('li', {},
          h('button', { type: 'button', onclick: () => select(t.id) },
            h('i', { class: `dot ${statusOf(t).cls}` }), t.name, h('span', { class: 'ver' }, statusOf(t).label))))));
    })),
    h('p', { class: 'tip' }, 'Press ', h('kbd', {}, '['), ' to collapse or expand the tools pane. Run one heavy service at a time (Splunk, n8n, Velociraptor, Suricata) to stay within 8 GB of RAM.'));
}

function stat(num, label) {
  return h('div', { class: 'card stat' }, h('div', { class: 'num' }, num), h('div', { class: 'lbl' }, label));
}

function toolView(t) {
  const s = statusOf(t);
  const cat = state.categories.find((c) => c.id === t.category);

  const stopButton = t.canStop
    ? h('button', { class: 'btn danger', type: 'button', onclick: (e) => stopTool(t, e.currentTarget) }, stopIcon(), 'Stop running')
    : null;
  const actions = t.installed && (t.actions.length || stopButton)
    ? h('div', { class: 'actions' }, t.actions.map((a) => actionButton(t, a)), stopButton)
    : null;

  const install = !t.installed
    ? h('div', { class: 'card install-box' },
      h('p', {}, h('strong', {}, 'Not installed. '), 'From the repo folder, run:'),
      exampleRow(t.installHint))
    : null;

  const meta = h('dl', { class: 'meta' },
    h('dt', {}, 'Version'), h('dd', {}, t.installedVersion || t.version || '-'),
    h('dt', {}, 'Status'), h('dd', {}, s.label),
    t.docs ? [h('dt', {}, 'Docs'), h('dd', {}, h('a', { href: t.docs, target: '_blank', rel: 'noopener noreferrer' }, t.docs))] : null);

  return h('div', { class: 'main-inner' },
    h('div', { class: 'crumb' }, cat ? cat.label : ''),
    h('div', { class: 'title-row' },
      h('h1', {}, t.name),
      h('span', { class: `pill ${s.cls}` }, h('i', { class: `dot ${s.cls}` }), s.label)),
    h('p', { class: 'lead' }, t.description),
    actions,
    install,
    livePanelFor(t.id),
    h('h2', {}, 'Details'),
    h('div', { class: 'card' }, meta),
    t.examples.length ? [h('h2', {}, 'Example commands'), h('div', { class: 'examples' }, t.examples.map(exampleRow))] : null);
}

function exampleRow(text) {
  return h('div', { class: 'example' },
    h('code', {}, text),
    h('button', {
      class: 'copy', type: 'button',
      onclick: async (e) => {
        try { await navigator.clipboard.writeText(text); e.target.textContent = 'Copied'; }
        catch { e.target.textContent = 'Copy failed'; }
        setTimeout(() => { e.target.textContent = 'Copy'; }, 1500);
      },
    }, 'Copy'));
}

function actionButton(tool, a) {
  const label = [a.label, a.admin ? h('span', { class: 'shield', title: 'Requires Administrator (UAC prompt)' }, ' (Admin)') : null];
  const cls = `btn${a.primary ? ' primary' : ''}`;
  if (a.type === 'web') {
    return h('a', { class: cls, href: a.url, target: '_blank', rel: 'noopener noreferrer' }, label);
  }
  return h('button', {
    class: cls, type: 'button',
    onclick: async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        const res = await fetch(`/api/tools/${encodeURIComponent(tool.id)}/actions/${a.index}`, {
          method: 'POST', headers: { 'X-Console-Token': TOKEN },
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
        toast(body.message || 'Done');
        setTimeout(refresh, 1500);
      } catch (err) {
        toast(err.message, true);
      } finally {
        btn.disabled = false;
      }
    },
  }, label);
}

// ---------------------------------------------------------------- live data views

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

const STATE_LABEL = {
  connected: ['running', 'Connected'],
  'needs-credentials': ['missing', 'Needs connection'],
  offline: ['idle', 'Not running'],
  error: ['missing', 'Error'],
  loading: ['idle', 'Loading...'],
};

function statePill(data) {
  const [cls, label] = STATE_LABEL[(data && data.state) || 'loading'] || STATE_LABEL.loading;
  return h('span', { class: `pill ${cls}` }, h('i', { class: `dot ${cls === 'idle' ? 'missing' : cls}` }), label,
    data && data.refreshing ? h('span', { class: 'spin', title: 'Refreshing' }) : null);
}

function notice(data, withConnectButton) {
  return h('div', { class: 'card notice' },
    h('p', {}, (data && data.message) || 'Waiting for data...'),
    withConnectButton && data && data.state === 'needs-credentials'
      ? h('button', { class: 'btn primary', type: 'button', onclick: () => select('connections') }, 'Open Connections')
      : null);
}

function sectionHead(title, data) {
  return h('div', { class: 'section-head' },
    h('h2', {}, title),
    statePill(data),
    data && data.updatedAt ? h('span', { class: 'updated' }, `updated ${ago(data.updatedAt)}`) : null);
}

function liveOverview() {
  if (!liveData) return h('p', { class: 'tip' }, 'Loading live data...');
  const s = liveData.splunk || {};
  const r = liveData.suricata || {};
  const n = liveData.n8n || {};
  const events24h = s.ingestion ? s.ingestion.reduce((a, b) => a + b.count24h, 0) : null;
  const hits = s.watches ? s.watches.filter((w) => w.count > 0) : [];

  return h('div', {},
    h('div', { class: 'section-head' }, h('h2', {}, 'Live'), h('span', { class: 'live-badge' }, h('i', {}), 'auto-refresh')),
    h('div', { class: 'live-cards' },
      liveCard('Splunk', s, s.state === 'connected'
        ? [`${fmt(events24h)} events / 24 h`, `health: ${s.health}`]
        : [s.message || '']),
      liveCard('Watchlist', s, s.state === 'connected'
        ? [hits.length ? `${hits.length} of ${s.watches.length} watches triggered` : 'No watch triggered in 24 h',
          hits.length ? hits.map((w) => w.title).slice(0, 2).join(', ') : 'all quiet']
        : ['Needs Splunk']),
      liveCard('Suricata IDS', r, r.state === 'connected'
        ? [`${r.alerts.length} recent alert${r.alerts.length === 1 ? '' : 's'}`, `last event ${ago(r.lastEvent)}`]
        : [r.message || '']),
      liveCard('n8n SOAR', n, n.state === 'connected'
        ? [`${n.workflows.filter((w) => w.active).length} active / ${n.workflows.length} workflows`,
          n.executions.length ? `last run: ${n.executions[0].status} ${ago(n.executions[0].startedAt)}` : 'no executions yet']
        : [n.message || ''])),
    s.state === 'connected' ? watchlistPanel(s, true) : null);
}

function liveCard(title, data, lines) {
  return h('div', { class: 'card live-card' },
    h('div', { class: 'live-card-head' }, h('strong', {}, title), statePill(data)),
    lines.filter(Boolean).map((l, i) => h('div', { class: i === 0 ? 'live-main' : 'live-sub' }, l)));
}

function livePanelFor(toolId) {
  if (!liveData) return null;
  if (toolId === 'splunk') return splunkPanel(liveData.splunk);
  if (toolId === 'suricata') return suricataPanel(liveData.suricata);
  if (toolId === 'n8n') return n8nPanel(liveData.n8n);
  return null;
}

function splunkPanel(s) {
  if (!s || s.state !== 'connected') return [sectionHead('Live data', s), notice(s, true)];
  return [
    sectionHead('Ingestion', s),
    h('div', { class: 'card table-card' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Index'), h('th', { class: 'num' }, 'Last 15 min'), h('th', { class: 'num' }, 'Last 24 h'), h('th', {}, 'Latest event'), h('th', {}, ''))),
      h('tbody', {}, s.ingestion.map((i) => h('tr', {},
        h('td', {}, h('i', { class: `dot ${i.count15m > 0 ? 'running' : i.count24h > 0 ? 'ready' : 'missing'}` }), ' ', i.index),
        h('td', { class: 'num' }, fmt(i.count15m)),
        h('td', { class: 'num' }, fmt(i.count24h)),
        h('td', {}, ago(i.lastEvent)),
        h('td', {}, h('a', { href: i.link, target: '_blank', rel: 'noopener noreferrer' }, 'Search'))))))),
    watchlistPanel(s, false),
  ];
}

function watchlistPanel(s, compact) {
  const rows = compact ? s.watches.filter((w) => w.count > 0) : s.watches;
  return [
    h('div', { class: 'section-head' }, h('h2', {}, compact ? 'Watchlist hits (24 h)' : 'Watchlist (24 h)'),
      h('span', { class: 'updated' }, `updated ${ago(s.updatedAt)}`)),
    rows.length
      ? h('div', { class: 'watch-list' }, rows.map((w) => h('a', {
        class: `card watch${w.count > 0 ? ' hit' : ''}`, href: w.link, target: '_blank', rel: 'noopener noreferrer',
        title: `Open in Splunk: ${w.spl}`,
      },
      h('span', { class: `sev ${w.severity}` }, w.severity),
      h('span', { class: 'watch-title' }, w.title, w.attack ? h('span', { class: 'attack' }, w.attack) : null),
      h('span', { class: 'watch-count' }, w.error ? '!' : fmt(w.count)),
      h('span', { class: 'watch-last' }, w.count > 0 ? ago(w.last) : ''))))
      : h('div', { class: 'card notice' }, h('p', {}, 'No watchlist events in the last 24 hours.')),
  ];
}

function suricataPanel(r) {
  if (!r || r.state !== 'connected') return [sectionHead('Latest IDS alerts', r), notice(r, false)];
  return [
    sectionHead('Latest IDS alerts', r),
    r.alerts.length
      ? h('div', { class: 'card table-card' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Time'), h('th', {}, 'Signature'), h('th', {}, 'Source'), h('th', {}, 'Destination'), h('th', { class: 'num' }, 'Sev'))),
        h('tbody', {}, r.alerts.map((a) => h('tr', {},
          h('td', { class: 'nowrap' }, ago(a.time)),
          h('td', {}, a.signature, h('div', { class: 'muted small' }, `${a.category || ''} · SID ${a.sid}`)),
          h('td', { class: 'mono' }, a.src), h('td', { class: 'mono' }, a.dest),
          h('td', { class: 'num' }, h('span', { class: `sev s${a.severity}` }, String(a.severity))))))))
      : h('div', { class: 'card notice' }, h('p', {}, `No alerts in the latest ${fmt(r.sampled)} Suricata events. That's normal on a quiet network.`)),
    h('p', { class: 'tip' }, `eve.json: ${r.fileSizeMB} MB · last event ${ago(r.lastEvent)} · event types: ` +
      Object.entries(r.types).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `${k} ${fmt(v)}`).join(', ')),
  ];
}

function n8nPanel(n) {
  if (!n || n.state !== 'connected') return [sectionHead('Workflows', n), notice(n, true)];
  return [
    sectionHead('Workflows', n),
    n.workflows.length
      ? h('div', { class: 'card table-card' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Workflow'), h('th', {}, 'State'), h('th', {}, 'Updated'))),
        h('tbody', {}, n.workflows.map((w) => h('tr', {},
          h('td', {}, h('a', { href: `${n.web}/workflow/${encodeURIComponent(w.id)}`, target: '_blank', rel: 'noopener noreferrer' }, w.name)),
          h('td', {}, h('span', { class: `pill ${w.active ? 'running' : ''}` }, w.active ? 'Active' : 'Inactive')),
          h('td', {}, ago(w.updatedAt)))))))
      : h('div', { class: 'card notice' }, h('p', {}, 'No workflows yet. Playbooks are built in the SOAR lab step.')),
    h('h2', {}, 'Recent executions'),
    n.executions.length
      ? h('div', { class: 'card table-card' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Workflow'), h('th', {}, 'Status'), h('th', {}, 'Trigger'), h('th', {}, 'Started'))),
        h('tbody', {}, n.executions.map((e) => h('tr', {},
          h('td', {}, e.workflow),
          h('td', {}, h('span', { class: `pill ${e.status === 'success' ? 'running' : e.status === 'error' ? 'missing' : ''}` }, e.status)),
          h('td', {}, e.mode || '-'), h('td', {}, ago(e.startedAt)))))))
      : h('div', { class: 'card notice' }, h('p', {}, 'No executions yet.')),
  ];
}

// ---------------------------------------------------------------- connections

function connectionsView() {
  const c = connections || {};
  return h('div', { class: 'main-inner' },
    h('div', { class: 'crumb' }, 'Settings'),
    h('h1', {}, 'Connections'),
    h('p', { class: 'lead' }, 'Credentials the console uses to read live data from your lab tools. They are checked against the running service, then encrypted with Windows DPAPI so only your Windows account can decrypt them. They are never sent back to the browser.'),

    connectionCard('splunk', c.splunk, 'Splunk', 'The admin login you chose when installing Splunk. Used for health, ingestion counts and the watchlist.', [
      { name: 'username', label: 'Username', type: 'text', value: 'admin', autocomplete: 'username' },
      { name: 'password', label: 'Password', type: 'password', autocomplete: 'current-password' },
    ]),
    connectionCard('n8n', c.n8n, 'n8n', 'Start n8n, open it, then go to Settings > n8n API > Create an API key and paste it here. Used for workflows and executions.', [
      { name: 'apiKey', label: 'API key', type: 'password', autocomplete: 'off' },
    ]),
    h('div', { class: 'card connection' },
      h('div', { class: 'conn-head' }, h('h3', {}, 'Suricata'), h('span', { class: 'pill ready' }, 'No credentials needed')),
      h('p', { class: 'muted' }, 'Read directly from C:\\Program Files\\Suricata\\log\\eve.json while Suricata runs.')),
    phoneCard());
}

// ---------------------------------------------------------------- phone access (Android app)

async function phoneApi(pathname, method, body) {
  const res = await fetch(pathname, {
    method,
    headers: { 'X-Console-Token': TOKEN, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const out = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(out.error || `HTTP ${res.status}`);
  return out;
}

function phoneCard() {
  const p = phone;
  if (!p) return null;
  const on = p.enabled && p.listening;
  const urls = p.addresses.map((a) => `${a.address}:${p.port}`);

  const toggle = h('button', {
    class: `btn${on ? '' : ' primary'}`, type: 'button',
    onclick: async (e) => {
      e.currentTarget.disabled = true;
      try {
        const out = await phoneApi('/api/phone/enable', 'POST', { enabled: !on });
        toast(out.message);
        if (!on) toast('If Windows Firewall asks about Node.js, allow it on Private networks only.');
        pairCode = null;
      } catch (err) { toast(err.message, true); }
      await loadPhone(true);
    },
  }, on ? 'Turn off' : 'Turn on phone access');

  const pairBlock = !on ? null : pairCode && Date.parse(pairCode.expiresAt) > Date.now()
    ? h('div', { class: 'pair-box' },
      h('div', { class: 'pair-step' }, '1. In the Security Labs app, enter this PC address and code:'),
      h('div', { class: 'pair-values' },
        h('div', {}, h('span', { class: 'muted small' }, 'PC address'), h('strong', { class: 'mono' }, urls[0] || 'no network found')),
        h('div', {}, h('span', { class: 'muted small' }, 'Pairing code'), h('strong', { class: 'pair-code' }, pairCode.code.replace(/(\d{3})(\d{3})/, '$1 $2')))),
      h('div', { class: 'pair-step' }, '2. Check that the phone shows this fingerprint before you tap Trust:'),
      h('div', { class: 'pair-fp mono' }, p.fingerprintShort),
      h('div', { class: 'muted small' }, `Code works once and expires at ${new Date(pairCode.expiresAt).toLocaleTimeString()}.`))
    : h('button', {
      class: 'btn primary', type: 'button',
      onclick: async () => {
        try { pairCode = await phoneApi('/api/phone/pair-code', 'POST'); } catch (err) { toast(err.message, true); }
        await loadPhone(true);
      },
    }, 'Pair a phone');

  return h('div', { class: 'card connection' },
    h('div', { class: 'conn-head' }, h('h3', {}, 'Phone access (Android app)'),
      h('span', { class: `pill ${on ? 'running' : ''}` }, on ? 'On, read-only' : p.enabled ? 'Starting...' : 'Off')),
    h('p', { class: 'muted' }, 'Lets paired phones on your home Wi-Fi VIEW tool status, live data, the watchlist and alerts over HTTPS. Phones can never start or stop tools or change settings. Off by default.'),
    on ? h('p', { class: 'small' }, 'Listening on ', urls.map((u, i) => [i ? ', ' : '', h('span', { class: 'mono' }, `https://${u}`)]),
      ' · certificate ', h('span', { class: 'mono' }, p.fingerprintShort)) : null,
    h('div', { class: 'conn-actions' }, toggle),
    pairBlock,
    p.devices.length ? [
      h('h4', { class: 'devices-head' }, 'Paired phones'),
      h('div', { class: 'devices' }, p.devices.map((d) => h('div', { class: 'device' },
        h('span', {}, h('strong', {}, d.name), h('span', { class: 'muted small' }, ` · paired ${ago(d.pairedAt)} · last seen ${ago(d.lastSeen)}`)),
        h('button', {
          class: 'btn danger', type: 'button',
          onclick: async () => {
            try { toast((await phoneApi(`/api/phone/devices/${encodeURIComponent(d.id)}`, 'DELETE')).message); } catch (err) { toast(err.message, true); }
            await loadPhone(true);
          },
        }, 'Revoke')))),
    ] : null);
}

async function loadPhone(force = false) {
  try {
    const res = await fetch('/api/phone', { cache: 'no-store' });
    if (res.ok) phone = await res.json();
    if (pairCode && (!phone.pairing.active || Date.parse(pairCode.expiresAt) <= Date.now())) pairCode = null;
    if (selected === 'connections') renderMain(force);
  } catch { /* ignore */ }
}

function connectionCard(id, info, title, help, fields) {
  const configured = info && info.configured;
  const form = h('form', {
    class: 'conn-form', autocomplete: 'on',
    onsubmit: async (e) => {
      e.preventDefault();
      const btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      btn.textContent = 'Checking...';
      const body = Object.fromEntries(new FormData(form).entries());
      try {
        const res = await fetch(`/api/connections/${id}`, {
          method: 'POST', headers: { 'X-Console-Token': TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        const out = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(out.error || `HTTP ${res.status}`);
        toast(out.message || 'Saved');
        form.reset();
        await loadConnections(true);
        refreshLive();
      } catch (err) {
        toast(err.message, true);
      } finally {
        btn.disabled = false;
        btn.textContent = configured ? 'Update' : 'Connect';
      }
    },
  },
  fields.map((f) => h('label', {}, h('span', {}, f.label),
    h('input', { name: f.name, type: f.type, value: f.value || null, autocomplete: f.autocomplete, required: true, spellcheck: 'false' }))),
  h('div', { class: 'conn-actions' },
    h('button', { class: 'btn primary', type: 'submit' }, configured ? 'Update' : 'Connect'),
    configured ? h('button', {
      class: 'btn', type: 'button',
      onclick: async () => {
        const res = await fetch(`/api/connections/${id}`, { method: 'DELETE', headers: { 'X-Console-Token': TOKEN } });
        const out = await res.json().catch(() => ({}));
        toast(out.message || out.error || 'Removed', !res.ok);
        await loadConnections(true);
        refreshLive();
      },
    }, 'Forget') : null));

  return h('div', { class: 'card connection' },
    h('div', { class: 'conn-head' }, h('h3', {}, title),
      h('span', { class: `pill ${configured ? 'running' : 'missing'}` }, configured ? `Saved ${ago(info.savedAt)}` : 'Not connected')),
    h('p', { class: 'muted' }, help),
    form);
}

async function loadConnections(force = false) {
  try {
    const res = await fetch('/api/connections', { cache: 'no-store' });
    if (!res.ok) return;
    connections = await res.json();
    const missing = Object.values(connections).some((c) => !c.configured);
    document.getElementById('connDot').className = `conn-dot${missing ? ' warn' : ' ok'}`;
    if (selected === 'connections') renderMain(force);
  } catch { /* server unreachable; refresh() reports it */ }
}

async function refreshLive() {
  if (document.hidden) return;
  try {
    const res = await fetch('/api/live', { cache: 'no-store' });
    if (!res.ok) return;
    liveData = await res.json();
    renderMain();
  } catch { /* ignore; next poll retries */ }
}

function stopIcon() {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  svg.classList.add('stop-icon');
  const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  for (const [k, v] of Object.entries({ x: 3.5, y: 3.5, width: 9, height: 9, rx: 1.5 })) rect.setAttribute(k, v);
  svg.append(rect);
  return svg;
}

/** "Stop running": stops services/processes and closes windows the console opened for this tool. */
async function stopTool(tool, btn) {
  btn.disabled = true;
  btn.classList.add('busy');
  toast(`Stopping ${tool.name}... (approve the UAC prompt if one appears)`);
  try {
    const res = await fetch(`/api/tools/${encodeURIComponent(tool.id)}/stop`, {
      method: 'POST', headers: { 'X-Console-Token': TOKEN },
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    toast(body.message || `Stopped ${tool.name}`);
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
    btn.classList.remove('busy');
    refresh();
  }
}

// ---------------------------------------------------------------- data

async function refresh() {
  if (document.hidden) return;
  try {
    const res = await fetch('/api/state', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state = await res.json();
    if (selected && selected !== 'connections' && !state.tools.some((t) => t.id === selected)) selected = null;
    renderNav();
    renderMemory();
    renderMain();
  } catch {
    if (!state) main.replaceChildren(h('div', { class: 'empty' }, 'Cannot reach the console server. Is start-console.ps1 still running?'));
  }
}

const hashMatch = location.hash.match(/^#tool\/([\w-]+)$/);
if (hashMatch) selected = hashMatch[1];
if (location.hash === '#connections') selected = 'connections';
refresh();
loadConnections();
loadPhone();
refreshLive();
setInterval(refresh, POLL_MS);
setInterval(refreshLive, LIVE_POLL_MS);
// Phone status (new pairings, last seen) refreshes while the Connections page is open.
setInterval(() => { if (selected === 'connections' && !document.hidden) loadPhone(); }, 5000);
document.addEventListener('visibilitychange', () => { refresh(); refreshLive(); });
