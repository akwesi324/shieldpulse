'use strict';
/* Security Labs Console - client. Builds all DOM with createElement/textContent (no innerHTML). */

const TOKEN = document.querySelector('meta[name="console-token"]').content;
const POLL_MS = 5000;
const app = document.getElementById('app');
const nav = document.getElementById('toolNav');
const main = document.getElementById('main');
const filterInput = document.getElementById('filter');
const toggle = document.getElementById('paneToggle');

let state = null;
let selected = null; // tool id or null for overview
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
  for (const c of children.flat()) {
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
  history.replaceState(null, '', id ? `#tool/${id}` : '#');
  if (window.matchMedia('(max-width: 720px)').matches) setCollapsed(true, false);
  renderNav();
  renderMain(true);
  main.focus({ preventScroll: true });
}

document.getElementById('homeLink').addEventListener('click', (e) => { e.preventDefault(); select(null); });

function renderMain(force = false) {
  if (!state) return;
  const tool = selected && state.tools.find((t) => t.id === selected);
  // Avoid re-rendering (and losing text selection) when nothing visible changed.
  const key = JSON.stringify(tool || state.tools.map((t) => [t.id, t.installed, t.running]));
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
    if (selected && !state.tools.some((t) => t.id === selected)) selected = null;
    renderNav();
    renderMemory();
    renderMain();
  } catch {
    if (!state) main.replaceChildren(h('div', { class: 'empty' }, 'Cannot reach the console server. Is start-console.ps1 still running?'));
  }
}

const hashMatch = location.hash.match(/^#tool\/([\w-]+)$/);
if (hashMatch) selected = hashMatch[1];
refresh();
setInterval(refresh, POLL_MS);
document.addEventListener('visibilitychange', refresh);
