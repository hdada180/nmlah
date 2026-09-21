/* Nemla UI: wires the form, the live event stream, the lists and the 3D scene together.
   Everything that comes from scanned hosts is inserted with textContent, never as HTML. */
(function () {
  'use strict';

  const I = window.NemlaI18n;
  const t = I.t;
  const C = window.NemlaScene;

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  function el(tag, props) {
    const node = document.createElement(tag);
    Object.keys(props || {}).forEach((k) => {
      if (k === 'class') node.className = props[k];
      else if (k === 'text') node.textContent = props[k];
      else node.setAttribute(k, props[k]);
    });
    for (let i = 2; i < arguments.length; i++) {
      const kid = arguments[i];
      if (kid != null) node.append(kid);
    }
    return node;
  }
  // sortable key for IPv4 and IPv6 addresses: IPv4 first, then IPv6 by its eight groups
  function ipKey(ip) {
    const bare = String(ip).split('%')[0];
    if (bare.indexOf(':') === -1) return [4, bare.split('.').reduce((a, b) => a * 256 + (+b || 0), 0)];
    const halves = bare.split('::');
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
    const fill = halves.length > 1 ? new Array(Math.max(0, 8 - head.length - tail.length)).fill('0') : [];
    return [6].concat(head.concat(fill, tail).map((g) => parseInt(g || '0', 16) || 0));
  }
  function cmpIp(a, b) {
    const x = ipKey(a), y = ipKey(b);
    for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; }
    return 0;
  }
  const portLabel = (p) => (p.proto && p.proto !== 'tcp' ? p.port + '/' + p.proto : String(p.port));
  const safe = (fn) => { try { return fn(); } catch (e) { return null; } };

  const state = {
    token: null, info: null, phase: 'idle', demo: false, job: null, es: null, stopDemo: null,
    hosts: new Map(), openPorts: 0, startedAt: 0, timer: null, finalSeconds: null,
    selected: null, tab: 'scan', logs: [], stage: 'discovery',
    prog: { done: 0, total: 0, hostIndex: 0, hostTotal: 0, pdone: 0, ptotal: 0 }, focusIp: null, lostShown: false,
    guard: { running: false, decoys: [], failed: {}, learning: true }, guardEs: null, guardDemo: null,
    alerts: [], alertLast: 0, diff: null, history: [], savedId: null
  };

  /* ---------------------------------------------------------------- link */

  function bootToken() {
    const m = /[#&]k=([\w-]+)/.exec(location.hash);
    if (m) {
      state.token = m[1];
      safe(() => sessionStorage.setItem('nemla.k', state.token));
      history.replaceState(null, '', location.pathname + location.search);
    } else {
      state.token = safe(() => sessionStorage.getItem('nemla.k'));
    }
  }

  async function api(path, opts) {
    opts = opts || {};
    const res = await fetch('/api/' + path, Object.assign({}, opts, {
      headers: Object.assign({ 'Content-Type': 'application/json', 'X-Nemla-Token': state.token || '' }, opts.headers)
    }));
    if (res.status === 401) showLost('session');
    return res;
  }

  function showLost(kind) {
    if (state.lostShown) return;
    state.lostShown = true;
    $('#lostTitle').textContent = t(kind === 'session' ? 'err.session.title' : 'err.gone.title');
    $('#lostBody').textContent = t(kind === 'session' ? 'err.session.body' : 'err.gone.body');
    $('#lost').hidden = false;
  }

  function startHeartbeat() {
    let misses = 0;
    setInterval(async () => {
      try { const r = await api('hb', { method: 'POST' }); misses = r.ok ? 0 : misses + 1; } catch (e) { misses += 1; }
      if (misses >= 3) showLost('gone');
    }, 10000);
    window.addEventListener('pagehide', () => {
      if (state.token && navigator.sendBeacon) navigator.sendBeacon('/api/bye?k=' + encodeURIComponent(state.token), '');
    });
  }

  /* --------------------------------------------------------------- scene */

  let scene = null;
  function initScene() {
    scene = new C($('#scene'), {
      onSelect: (ip) => {
        state.selected = ip; renderInspector(); renderHosts(true); updateInsets();
        if (ip && !state.hosts.has(ip)) focusAlertFor(ip); // an intruder marker, not a scanned host
      },
      onHover: showTip
    });
  }

  function showTip(info) {
    const tip = $('#tip');
    if (!info) { tip.hidden = true; return; }
    const h = state.hosts.get(info.ip);
    tip.replaceChildren(el('b', { text: info.ip }),
      el('span', { text: h && h.state === 'done' ? h.open_ports.length + ' ' + t('hud.open').toLowerCase() : (h && h.os_guess) || '…' }));
    tip.style.left = info.x + 'px'; tip.style.top = info.y + 'px';
    tip.hidden = false;
  }

  function updateInsets() {
    const w = window.innerWidth, h = window.innerHeight;
    let l = 0, r = 0, top = 0, bottom = 0;
    const panels = [$('#dock'), $('#inspector')];
    panels.forEach((p) => {
      if (!p || p.hidden) return;
      const b = p.getBoundingClientRect();
      if (b.width > w * 0.7) {
        if (b.top + b.height / 2 > h / 2) bottom = Math.max(bottom, h - b.top + 8); else top = Math.max(top, b.bottom);
      } else if (b.left + b.width / 2 < w / 2) l = Math.max(l, b.right + 16);
      else r = Math.max(r, w - b.left + 16);
    });
    const hud = $('#hud'), legend = $('#legend');
    if (w <= 900) {
      // the HUD sits at the top and may have wrapped into two rows: reserve what it really takes
      top = Math.max(top, Math.ceil(hud.getBoundingClientRect().bottom) + 8);
      if (state.selected) bottom = Math.max(bottom, $('#inspector').getBoundingClientRect().height + 12);
    }
    scene.setInsets(l, r, top, bottom);
    // the colour legend lives in a bottom corner (the left one in right-to-left): the HUD keeps clear of it
    let hl = l, hr = r;
    if (w > 900 && legend && getComputedStyle(legend).display !== 'none') {
      const b = legend.getBoundingClientRect();
      if (b.left + b.width / 2 < w / 2) hl = Math.max(hl, b.right + 16); else hr = Math.max(hr, w - b.left + 16);
    }
    const root = document.documentElement.style;
    root.setProperty('--il', (w <= 900 ? 0 : l) + 'px'); root.setProperty('--ir', (w <= 900 ? 0 : r) + 'px');
    root.setProperty('--hud-l', (w <= 900 ? 0 : hl) + 'px'); root.setProperty('--hud-r', (w <= 900 ? 0 : hr) + 'px');
    const hudBox = hud.getBoundingClientRect();
    root.setProperty('--hud-h', Math.ceil(hudBox.height) + 'px'); root.setProperty('--hud-b', Math.ceil(hudBox.bottom) + 'px');
  }

  /* -------------------------------------------------------------- render */

  let dirtyFlag = false;
  function dirty() {
    if (dirtyFlag) return;
    dirtyFlag = true;
    requestAnimationFrame(() => { dirtyFlag = false; renderStats(); renderHosts(false); renderInspector(true); });
  }

  const fmtSec = (s) => (s < 60 ? s.toFixed(1) + 's' : Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's');

  function renderStats() {
    $('#statHosts').textContent = state.hosts.size;
    $('#statPorts').textContent = state.openPorts;
    const fc = countFindings(), sf = $('#statFindings');
    sf.textContent = fc.n; sf.classList.toggle('hot', fc.high > 0);
    const c = $('#hostCount');
    c.textContent = state.hosts.size || ''; c.dataset.n = state.hosts.size;
    const secs = state.finalSeconds != null ? state.finalSeconds : state.startedAt ? (Date.now() - state.startedAt) / 1000 : 0;
    $('#statTime').textContent = fmtSec(secs);
    $('#barFill').style.width = (progress() * 100).toFixed(1) + '%';
    if (state.phase === 'running') document.title = 'Nemla · ' + state.hosts.size + ' · ' + state.openPorts;
    else document.title = 'Nemla · نملة';
  }

  function progress() {
    const p = state.prog;
    if (state.phase === 'done' || state.phase === 'stopped') return 1;
    if (state.phase !== 'running') return 0;
    if (state.stage === 'discovery') return 0.2 * (p.total ? p.done / p.total : 0);
    return 0.2 + 0.8 * (p.ptotal ? p.pdone / p.ptotal : 0);
  }

  function renderStatus() {
    const key = state.phase === 'idle' ? 'ready' : state.phase;
    const s = $('#status');
    s.dataset.state = state.phase;
    $('#statusText').textContent = state.demo && state.phase === 'running' ? t('status.demo') : t('status.' + key);
    $('#hud').dataset.state = state.phase;
    const running = state.phase === 'running';
    $('#btnStop').hidden = !running;
    const start = $('#btnStart');
    start.disabled = running;
    $('#btnExport').disabled = !(state.phase === 'done' || state.phase === 'stopped') || state.demo || !(state.job || state.savedId);
    $('#demoBadge').hidden = !state.demo;
    $('#hint').hidden = state.hosts.size > 0 || running;
    renderPhaseText();
  }

  function renderPhaseText() {
    let text;
    const secs = state.finalSeconds != null ? state.finalSeconds.toFixed(1) : '0';
    if (state.phase === 'running') text = state.stage === 'discovery' ? t('phase.discovery') : t('phase.ports', { ip: state.focusIp || '…' });
    else if (state.phase === 'done') text = state.hosts.size ? t('phase.done', { sec: secs }) : t('phase.nohosts');
    else if (state.phase === 'stopped') text = t('phase.stopped', { sec: secs });
    else if (state.phase === 'error') text = t('phase.error');
    else text = t('phase.idle');
    $('#phaseText').textContent = text;
  }

  const hostEls = new Map();
  function portsColor(port) { return C.CATEGORIES[C.categoryOf(port)].color; }

  const SEV_RANK = { high: 3, medium: 2, low: 1, info: 0 };
  function riskOf(h) {
    let best = null;
    (h.findings || []).forEach((f) => {
      if (f.severity === 'high') best = 'high';
      else if (f.severity === 'medium' && best !== 'high') best = 'medium';
    });
    return best;
  }
  const findingVars = (f) => Object.assign({ port: f.port, host: f.host }, f.params || {});
  const findingText = (f) => t('find.' + f.id, findingVars(f));
  const findingWhy = (f) => (I.has('finddesc.' + f.id) ? t('finddesc.' + f.id, findingVars(f)) : '');
  const findingFix = (f) => (I.has('findfix.' + f.id) ? t('findfix.' + f.id, findingVars(f)) : '');
  const pct = (x) => Math.round(x * 100);
  function osLabel(h) {
    const o = h.os;
    if (!o || o.confidence == null || o.family === 'unknown') return h.os_guess || '';
    return (o.name || h.os_guess) + ' · ' + t('insp.os.conf', { n: pct(o.confidence) }) + (o.heuristic ? ' · ' + t('insp.est') : '');
  }
  function countFindings() {
    let n = 0, high = 0;
    state.hosts.forEach((h) => (h.findings || []).forEach((f) => { if (f.severity !== 'info') { n += 1; if (f.severity === 'high') high += 1; } }));
    return { n, high };
  }
  function applyRisk(h) { scene.setHostRisk(h.ip, riskOf(h)); }

  function renderHosts(force) {
    const list = $('#hostList');
    const q = $('#hostFilter').value.trim().toLowerCase();
    const hosts = Array.from(state.hosts.values()).sort((a, b) => cmpIp(a.ip, b.ip)).filter((h) => {
      if (!q) return true;
      return h.ip.includes(q) || (h.os_guess || '').toLowerCase().includes(q) ||
        h.open_ports.some((p) => String(p.port) === q || (p.service || '').toLowerCase().includes(q));
    });
    const els = hosts.map((h) => {
      let li = hostEls.get(h.ip);
      const sig = h.state + '|' + h.open_ports.length + '|' + (h.os_guess || '') + '|' + (state.selected === h.ip) + '|' + I.lang + '|' + riskOf(h);
      if (!li) {
        li = el('li', { class: 'host', tabindex: '0', role: 'button' });
        li.addEventListener('click', () => scene.select(state.selected === h.ip ? null : h.ip));
        li.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); li.click(); } });
        li.addEventListener('pointerenter', () => scene.hover(h.ip));
        li.addEventListener('pointerleave', () => scene.hover(null));
        hostEls.set(h.ip, li);
      }
      if (li._sig !== sig || force) {
        li._sig = sig;
        li.dataset.state = h.state;
        li.dataset.risk = riskOf(h) || '';
        li.classList.toggle('selected', state.selected === h.ip);
        const dots = el('span', { class: 'dots' });
        h.open_ports.slice(0, 7).forEach((p) => { const i = el('i'); i.style.setProperty('--c', portsColor(p.port)); i.title = p.port + ' ' + p.service; dots.append(i); });
        if (h.open_ports.length > 7) dots.append(el('em', { text: t('hosts.more', { n: h.open_ports.length - 7 }) }));
        li.replaceChildren(
          el('span', { class: 'state' }),
          el('span', {}, el('span', { class: 'ip', text: h.ip }), el('span', { class: 'os', text: h.os_guess || h.method || '' })),
          dots
        );
      }
      return li;
    });
    // reorder in place: re-inserting a node would restart its entrance animation
    let ref = list.firstChild;
    els.forEach((li) => { if (li === ref) ref = ref.nextSibling; else list.insertBefore(li, ref); });
    while (ref) { const next = ref.nextSibling; list.removeChild(ref); ref = next; }
    $('#hostEmpty').hidden = state.hosts.size > 0;
    if (state.hosts.size && !hosts.length) { $('#hostEmpty').hidden = false; $('#hostEmpty').textContent = t('hosts.nomatch'); }
    else $('#hostEmpty').textContent = t('hosts.empty');
  }

  function renderLog() {
    const list = $('#logList');
    list.replaceChildren(...state.logs.slice(-200).map((l) =>
      el('li', { class: l.warn ? 'warn' : '' }, el('time', { text: l.time }), el('span', { class: 'msg', text: l.msg }))));
    $('#logEmpty').hidden = state.logs.length > 0;
    const pane = $('#pane-log');
    if (state.tab === 'log') pane.scrollTop = pane.scrollHeight;
  }

  function addLog(msg, warn) {
    const d = new Date();
    const time = [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':');
    state.logs.push({ time, msg, warn });
    if (state.logs.length > 400) state.logs.shift();
    if (state.tab === 'log') renderLog();
  }

  /* ------------------------------------------------------------ inspector */

  function summary(h) {
    const lines = [h.ip + (osLabel(h) ? ' - ' + osLabel(h) : '')];
    h.open_ports.forEach((p) => {
      const product = [p.product, p.version].filter(Boolean).join(' ');
      lines.push('  ' + p.port + '/' + (p.proto || 'tcp') + '  ' + p.service + (product ? '  ' + product : '') + (p.banner ? '  ' + p.banner : ''));
    });
    if (!h.open_ports.length) lines.push('  ' + t('insp.noports'));
    (h.findings || []).filter((f) => f.severity !== 'info').forEach((f) => lines.push('  [' + t('sev.' + f.severity) + '] ' + findingText(f)));
    return lines.join('\n');
  }

  function renderInspector(soft) {
    const box = $('#inspector'), ip = state.selected, h = ip && state.hosts.get(ip);
    if (!h) { if (!box.hidden) { box.hidden = true; updateInsets(); } return; }
    const wasHidden = box.hidden;
    box.hidden = false;
    $('#inspIp').textContent = h.ip;
    const badges = $('#inspBadges');
    badges.replaceChildren(...[osLabel(h)].filter(Boolean).map((x) => el('span', { class: 'badge', text: x })));
    const ev = $('#inspEvidence'), why = (h.os && h.os.evidence) || [];
    ev.hidden = !why.length;
    ev.title = t('insp.os.why');
    ev.replaceChildren(...why.slice(0, 6).map((line) => el('li', { text: line })));
    const kv = $('#inspKv'), rows = [];
    if (h.mac) rows.push(['insp.mac', h.mac]);
    if (h.vendor) rows.push(['insp.vendor', h.vendor]);
    if (h.ttl) rows.push(['TTL', String(h.ttl)]);
    if (h.method) rows.push(['insp.via', h.method]);
    kv.replaceChildren(...rows.flatMap(([k, v]) => [el('dt', { text: k.startsWith('insp.') ? t(k) : k }), el('dd', { text: v })]));
    const cnt = $('#inspCount'); cnt.textContent = h.open_ports.length || ''; cnt.dataset.n = h.open_ports.length;

    const finds = (h.findings || []).slice().sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
    const fl = $('#inspFindings'), fsig = h.ip + '|' + finds.length + '|' + h.state + '|' + I.lang;
    const shown = finds.filter((f) => f.severity !== 'info').length;
    const fcnt = $('#findCount'); fcnt.textContent = shown || ''; fcnt.dataset.n = shown;
    if (!soft || fl._sig !== fsig) {
      fl._sig = fsig;
      const rows = finds.map((f) => {
        const body = el('div', { class: 'fbody' }, el('span', { text: findingText(f) }));
        if (f.severity !== 'info' && (findingWhy(f) || f.evidence)) {
          const more = el('details', {}, el('summary', { text: t('insp.more') }));
          if (findingWhy(f)) more.append(el('p', { text: findingWhy(f) }));
          if (findingFix(f)) more.append(el('p', {}, el('b', { text: t('insp.fix') + ': ' }), document.createTextNode(findingFix(f))));
          if (f.evidence) more.append(el('p', { class: 'fev', text: t('insp.evidence') + ': ' + f.evidence + (f.confidence != null ? ' (' + t('insp.conf', { n: pct(f.confidence) }) + ')' : '') }));
          body.append(more);
        }
        return el('li', { 'data-sev': f.severity }, el('span', { class: 'sev-chip', text: t('sev.' + f.severity) }), body);
      });
      if (!rows.length && (h.state === 'done' || state.phase !== 'running')) rows.push(el('li', { class: 'ok' }, el('span', { text: t('insp.nofindings') })));
      fl.replaceChildren(...rows);
    }

    const ul = $('#inspPorts');
    const sig = h.ip + '|' + h.open_ports.length + '|' + h.state + '|' + I.lang;
    if (!soft || ul._sig !== sig) {
      ul._sig = sig;
      const items = h.open_ports.map((p) => {
        const product = [p.product, p.version].filter(Boolean).join(' ');
        const tls = p.tls || {};
        const metaBits = [p.title, tls.version && [tls.version, tls.subject, tls.not_after && ('→ ' + tls.not_after)].filter(Boolean).join(' · ')].filter(Boolean);
        const conf = p.confidence == null ? null : el('span', { class: 'conf' + (p.heuristic ? ' guess' : ''), title: p.evidence || '', text: pct(p.confidence) + '%' + (p.heuristic ? ' ~' : '') });
        const li = el('li', {}, el('div', { class: 'row' }, el('span', { class: 'pnum', text: portLabel(p) }), el('span', { class: 'psvc', text: p.service }), conf),
          product ? el('span', { class: 'prod', text: product }) : null,
          metaBits.length ? el('span', { class: 'meta', text: metaBits.join(' | ') }) : null,
          el('code', { class: p.banner ? '' : 'none', text: p.banner || t('insp.nobanner') }));
        li.style.setProperty('--c', portsColor(p.port));
        return li;
      });
      if (!items.length) items.push(el('li', {}, el('code', { class: 'none', text: h.state === 'done' || state.phase !== 'running' ? t('insp.noports') : t('insp.pending') })));
      ul.replaceChildren(...items);
    }
    const udp = $('#inspUdp'), quiet = (h.udp_unconfirmed || []).map((u) => u.port);
    udp.hidden = !quiet.length;
    udp.textContent = quiet.length ? t('insp.udp.unconfirmed', { ports: quiet.join(', ') }) : '';
    if (wasHidden) updateInsets();
  }

  /* --------------------------------------------------------------- events */

  function resetRun() {
    if (state.es) { state.es.close(); state.es = null; }
    if (state.stopDemo) { state.stopDemo(); state.stopDemo = null; }
    clearInterval(state.timer);
    state.hosts.clear(); hostEls.clear(); state.openPorts = 0; state.logs = []; state.finalSeconds = null; state.savedId = null;
    state.selected = null; state.focusIp = null; state.stage = 'discovery';
    state.prog = { done: 0, total: 0, hostIndex: 0, hostTotal: 0, pdone: 0, ptotal: 0 };
    scene.clear();
    restoreAlarms();
    state.diff = null; renderDiff();
    renderLog(); renderHosts(true); renderInspector();
  }

  function beginRun(startMs) {
    state.phase = 'running';
    state.startedAt = startMs || Date.now();
    clearInterval(state.timer);
    state.timer = setInterval(renderStats, 100);
    scene.setPhase('discovery');
    setTab('hosts');
    renderStatus(); renderStats();
  }

  function handle(ev) {
    switch (ev.type) {
      case 'start': if (state.phase !== 'running') beginRun(ev.started * 1000); else state.startedAt = ev.started * 1000; break;
      case 'phase':
        state.stage = ev.phase;
        if (ev.phase === 'ports') { state.prog.hostTotal = ev.total; scene.setPhase('ports'); }
        else { scene.setPhase('discovery'); state.prog.total = ev.total; }
        renderStatus(); break;
      case 'progress':
        if (ev.phase === 'discovery') { state.prog.done = ev.done; state.prog.total = ev.total; }
        else { state.prog.pdone = ev.done; state.prog.ptotal = ev.total; }
        dirty(); break;
      case 'host': {
        if (state.hosts.has(ev.ip)) break;
        const h = { ip: ev.ip, mac: ev.mac, method: ev.method, state: 'up', os_guess: '', ttl: null, open_ports: [] };
        state.hosts.set(ev.ip, h); scene.addHost(h); dirty(); break;
      }
      case 'host_start': {
        const h = state.hosts.get(ev.ip); if (!h) break;
        h.state = 'scanning'; state.focusIp = ev.ip; state.prog.hostIndex = ev.index; state.prog.hostTotal = ev.total;
        scene.setHostState(ev.ip, 'scanning'); renderPhaseText(); dirty(); break;
      }
      case 'port': {
        const h = state.hosts.get(ev.ip); if (!h || h.open_ports.some((p) => p.port === ev.port && (p.proto || 'tcp') === (ev.proto || 'tcp'))) break;
        const rec = Object.assign({}, ev); delete rec.type; delete rec.ip;
        h.open_ports.push(rec); state.openPorts += 1;
        scene.addPort(ev.ip, ev); dirty(); break;
      }
      case 'host_done': {
        const h = state.hosts.get(ev.host.ip); if (!h) break;
        state.openPorts += ev.host.open_ports.length - h.open_ports.length;
        Object.assign(h, ev.host, { state: 'done' });
        ev.host.open_ports.forEach((p) => scene.addPort(h.ip, p));
        scene.setHostState(h.ip, 'done'); applyRisk(h); dirty(); break;
      }
      case 'log': addLog(ev.msg); break;
      case 'done': finish(ev); break;
      case 'error': fail(ev.msg); break;
      default: break;
    }
  }

  function finish(ev) {
    clearInterval(state.timer);
    ev.hosts.forEach((src) => {
      let h = state.hosts.get(src.ip);
      if (!h) { h = { ip: src.ip, method: src.discovery, open_ports: [] }; state.hosts.set(src.ip, h); scene.addHost(h); }
      Object.assign(h, src, { state: 'done' });
      src.open_ports.forEach((p) => scene.addPort(h.ip, p));
      scene.setHostState(h.ip, 'done'); applyRisk(h);
    });
    state.hosts.forEach((h) => { if (h.state === 'scanning') { h.state = 'up'; scene.setHostState(h.ip, 'up'); } });
    state.openPorts = Array.from(state.hosts.values()).reduce((n, h) => n + h.open_ports.length, 0);
    state.finalSeconds = ev.meta.duration;
    state.diff = ev.diff || null;
    renderDiff(); applyDiffMarks();
    state.phase = ev.meta.cancelled ? 'stopped' : 'done';
    state.stage = 'ports';
    scene.setPhase('done');
    if (state.es) { state.es.close(); state.es = null; }
    renderStatus(); dirty();
    toast(ev.meta.cancelled ? t('toast.stopped') : t('toast.done', { hosts: state.hosts.size, ports: state.openPorts, findings: countFindings().n }));
  }

  function fail(msg) {
    clearInterval(state.timer);
    state.phase = 'error'; scene.setPhase('done');
    if (state.es) { state.es.close(); state.es = null; }
    addLog(msg, true); toast(msg || t('err.generic'), 'error'); renderStatus();
  }

  function attach(jobId) {
    state.job = jobId;
    if (state.phase !== 'running') beginRun();
    const es = new EventSource('/api/events?job=' + encodeURIComponent(jobId) + '&k=' + encodeURIComponent(state.token));
    state.es = es;
    es.onmessage = (m) => { const ev = safe(() => JSON.parse(m.data)); if (ev) handle(ev); };
    es.onerror = () => { if (es.readyState === EventSource.CLOSED && state.phase === 'running') showLost('gone'); };
  }

  /* ----------------------------------------------------------------- scan */

  function showFormError(msg) {
    const box = $('#formError');
    box.textContent = msg || ''; box.hidden = !msg;
  }

  function hasConsent() { return safe(() => localStorage.getItem('nemla.ack')) === '1'; }

  function askConsent() {
    return new Promise((resolve) => {
      const dlg = $('#consent'), check = $('#consentCheck'), ok = $('#consentOk'), cancel = $('#consentCancel');
      check.checked = false; ok.disabled = true;
      const done = (value) => { dlg.close(); check.onchange = ok.onclick = cancel.onclick = null; dlg.oncancel = null; resolve(value); };
      check.onchange = () => { ok.disabled = !check.checked; };
      ok.onclick = () => { safe(() => localStorage.setItem('nemla.ack', '1')); done(true); };
      cancel.onclick = () => done(false);
      dlg.oncancel = (e) => { e.preventDefault(); done(false); };
      dlg.showModal();
    });
  }

  async function startScan() {
    showFormError('');
    const target = $('#target').value.trim();
    if (!target) { showFormError(t('scan.needtarget')); $('#target').focus(); return; }
    if (!state.token) { toast(t('toast.nodemo'), 'error'); return; }
    if (!hasConsent() && !(await askConsent())) return;

    const profile = ($('input[name="depth"]:checked') || {}).value || 'quick';
    const body = {
      target, profile, ports: $('#ports').value, no_ping: $('#optNoPing').checked, no_os: !$('#optOs').checked,
      no_banner: !$('#optBanner').checked, udp: $('#optUdp').checked, threads: +$('#optThreads').value || 150, timeout: +$('#optTimeout').value || 0.7,
      lang: I.lang, authorized: true
    };
    state.demo = false;
    let res;
    try { res = await api('scan', { method: 'POST', body: JSON.stringify(body) }); } catch (e) { showLost('gone'); return; }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { showFormError(data.error || t('err.generic')); return; }
    resetRun();
    attach(data.job);
  }

  function stopScan() {
    if (state.demo) {
      if (state.stopDemo) state.stopDemo(); state.stopDemo = null; clearInterval(state.timer);
      state.finalSeconds = (Date.now() - state.startedAt) / 1000; state.phase = 'stopped'; scene.setPhase('done');
      state.hosts.forEach((h) => { if (h.state === 'scanning') { h.state = 'up'; scene.setHostState(h.ip, 'up'); } });
      renderStatus(); dirty(); return;
    }
    api('stop', { method: 'POST' }).catch(() => {});
  }

  function startDemo() {
    resetRun();
    state.demo = true; state.job = null;
    beginRun(Date.now());
    toast(t('toast.demo'));
    state.stopDemo = window.NemlaDemo.run((ev) => { if (ev.type === 'done') ev.meta.cancelled = false; handle(ev); });
  }

  function download(fmt) {
    if ((!state.job && !state.savedId) || state.demo) return;
    const path = state.savedId ? 'history/report?id=' + encodeURIComponent(state.savedId) : 'report?job=' + encodeURIComponent(state.job);
    const a = el('a', { href: '/api/' + path + '&fmt=' + fmt + '&lang=' + I.lang + '&k=' + encodeURIComponent(state.token), download: '' });
    document.body.append(a); a.click(); a.remove();
    closeMenu();
  }

  /* ------------------------------------------------------------------- ui */

  /* --------------------------------------------- what changed since last scan */

  function renderDiff() {
    const card = $('#diffCard'), d = state.diff;
    if (!d) { card.hidden = true; return; }
    card.hidden = false;
    const s = d.summary || {};
    $('#diffSub').textContent = d.against && d.against.scan_time ? t('diff.sub', { time: d.against.scan_time }) : '';
    const chips = $('#diffChips'), list = $('#diffList');
    list.replaceChildren();
    if (!s.changed) { chips.replaceChildren(el('p', { class: 'diff-none', text: t('diff.none') })); return; }
    const parts = [];
    [['new', 'diff.chip.new', s.new_hosts], ['gone', 'diff.chip.gone', s.gone_hosts], ['opened', 'diff.chip.opened', s.opened_ports],
      ['closed', 'diff.chip.closed', s.closed_ports], ['bad', 'diff.chip.findings', s.new_findings]].forEach(([cls, key, n]) => {
      if (n) parts.push(el('span', { class: 'diff-chip ' + cls, text: t(key, { n }) }));
    });
    chips.replaceChildren(...parts);
    const rows = [];
    const row = (ip, text) => {
      const li = el('li', {}, el('b', { text: ip }), document.createTextNode('  ' + text));
      li.addEventListener('click', () => { if (state.hosts.has(ip)) scene.select(ip); });
      rows.push(li);
    };
    (d.new_hosts || []).forEach((ip) => row(ip, t('diff.new_host')));
    (d.gone_hosts || []).forEach((ip) => row(ip, t('diff.gone_host')));
    Object.keys(d.hosts || {}).forEach((ip) => {
      const e = d.hosts[ip];
      e.opened.forEach((port) => row(ip, t('diff.opened', { port })));
      e.closed.forEach((port) => row(ip, t('diff.closed', { port })));
      e.changed.forEach((c) => row(ip, t('diff.service', { port: c.port, old: c.from, new: c.to })));
      if (e.os) row(ip, t('diff.os', { old: e.os.from, new: e.os.to }));
      e.new_findings.forEach((f) => row(ip, t('diff.new_finding', { sev: t('sev.' + f.severity), text: findingText(f) })));
      e.resolved_findings.forEach((f) => row(ip, t('diff.resolved', { sev: t('sev.' + f.severity), text: findingText(f) })));
    });
    list.replaceChildren(...rows.slice(0, 80));
  }

  function applyDiffMarks() {
    const d = state.diff;
    if (!d) return;
    (d.new_hosts || []).forEach((ip) => scene.setHostNew(ip));
    (d.gone_hosts || []).forEach((ip) => scene.addGhost(ip));
  }

  function setTab(name) {
    state.tab = name;
    $$('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
    $$('.pane').forEach((p) => { p.hidden = p.id !== 'pane-' + name; });
    if (name === 'log') renderLog();
    if (name === 'history') loadHistory();
    if (name === 'guard') { state.alertLast = state.alerts.length; renderAlertCount(); }
  }

  /* ------------------------------------------------------------- history */

  async function loadHistory() {
    try {
      const res = await api('history');
      const data = await res.json();
      state.history = data.scans || [];
    } catch (e) { state.history = []; }
    renderHistory();
  }

  function renderHistory() {
    const list = $('#historyList');
    list.replaceChildren(...state.history.map((s) => {
      const findings = s.findings || {};
      const li = el('li', { tabindex: '0', role: 'button' },
        el('span', { class: 'target', text: s.target }),
        el('span', { class: 'when', text: s.scan_time }),
        el('span', { class: 'sums' }, document.createTextNode(t('history.hosts', { n: s.hosts }) + ' · ' + t('history.ports', { n: s.open_ports })),
          findings.high ? el('b', { text: '  ' + findings.high + ' ' + t('sev.high') }) : null));
      const open = () => openSaved(s.id);
      li.addEventListener('click', open);
      li.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
      return li;
    }));
    $('#historyEmpty').hidden = state.history.length > 0;
  }

  async function openSaved(id) {
    if (state.phase === 'running') return;
    let data, diff = null;
    try {
      const res = await api('history/scan?id=' + encodeURIComponent(id));
      if (!res.ok) throw new Error('missing');
      data = await res.json();
      const at = state.history.findIndex((s) => s.id === id);
      const older = at >= 0 ? state.history.slice(at + 1).find((s) => s.target === state.history[at].target) : null;
      if (older) {
        const dres = await api('history/diff?a=' + encodeURIComponent(older.id) + '&b=' + encodeURIComponent(id));
        if (dres.ok) diff = await dres.json();
      }
    } catch (e) { toast(t('history.failed'), 'error'); return; }
    resetRun();
    state.demo = false; state.job = null; state.savedId = id;
    setTab('hosts');
    finish({ hosts: data.hosts, meta: { duration: data.duration_seconds || 0, cancelled: false }, diff });
    state.savedId = id;
    renderStatus();
    toast(t('history.loaded', { time: data.scan_time || '' }));
  }

  /* -------------------------------------------------------------- guard */

  function renderAlertCount() {
    const unseen = state.tab === 'guard' ? 0 : state.alerts.length - state.alertLast;
    const c = $('#alertCount');
    c.textContent = unseen > 0 ? unseen : ''; c.dataset.n = unseen;
    const chip = $('#guardChip');
    chip.classList.toggle('alert', unseen > 0);
  }

  function renderGuardStatus() {
    const g = state.guard;
    $('#guardSwitch').checked = g.running;
    $('#guardChip').hidden = !g.running;
    const st = $('#guardState');
    st.classList.toggle('on', g.running);
    if (!g.running) st.textContent = t('guard.off');
    else if (g.learning) st.textContent = t('guard.learning');
    else st.textContent = t('guard.on', { n: g.decoys.length });
    const box = $('#guardDecoys');
    box.hidden = !g.running;
    if (g.running) {
      $('#decoyChips').replaceChildren(...g.decoys.map((p) => el('span', { class: 'decoy', text: String(p) })));
      const failedPorts = Object.keys(g.failed || {});
      $('#decoyFailed').hidden = !failedPorts.length;
      if (failedPorts.length) $('#decoyFailed').textContent = t('guard.failed', { ports: failedPorts.join(', ') });
    }
  }

  function alertTitle(kind, gateway) {
    return t('guard.k.' + (kind === 'arp_change' && gateway ? 'arp_gateway' : kind));
  }
  function alertText(a) {
    const d = a.detail || {};
    if (a.kind === 'guard_notice') return t('guard.t.notice.' + d.code, d);
    let text = t('guard.t.' + (a.kind === 'arp_change' && d.gateway ? 'arp_gateway' : a.kind),
      Object.assign({ src: a.src_ip, ip: a.src_ip, mac: a.mac }, d));
    if (a.kind === 'new_device') {
      if (d.vendor) text += t('guard.t.new_device_vendor', { vendor: d.vendor });
      else if (d.local) text += t('guard.t.new_device_local');
    }
    return text;
  }
  function alertNextStep(kind) {
    if (kind === 'tripwire') return t('guard.n.tripwire');
    if (kind === 'new_device') return t('guard.n.new_device');
    if (kind === 'arp_change' || kind === 'arp_dup') return t('guard.n.arp');
    if (kind === 'baseline') return t('guard.n.baseline');
    return '';
  }
  const fmtClock = (ts) => new Date(ts * 1000).toLocaleTimeString();

  function flashScreen() {
    const f = $('#flash');
    f.classList.remove('on'); void f.offsetWidth; f.classList.add('on');
  }

  const alertEls = new Map();
  function renderAlerts() {
    const list = $('#alertList');
    const rows = state.alerts.slice().reverse().map((a) => {
      let li = alertEls.get(a.id);
      if (!li) {
        li = el('li', { class: 'alert', 'data-sev': a.severity });
        const actions = el('div', { class: 'alert-actions' });
        if (a.kind !== 'baseline' && a.src_ip) {
          const showBtn = el('button', { type: 'button', class: 'btn', text: t('guard.act.show') });
          showBtn.addEventListener('click', () => showOnMap(a.src_ip));
          actions.append(showBtn);
        }
        if (a.kind === 'new_device' && a.mac) {
          const trustBtn = el('button', { type: 'button', class: 'btn', text: t('guard.act.trust') });
          trustBtn.addEventListener('click', () => trustDevice(a.mac, li));
          actions.append(trustBtn);
        }
        if (a.kind !== 'baseline' && a.src_ip) {
          const blockBtn = el('button', { type: 'button', class: 'btn danger', text: t('guard.act.block') });
          blockBtn.addEventListener('click', () => showBlockDialog(a.src_ip));
          actions.append(blockBtn);
        }
        li.append(
          el('div', { class: 'alert-top' }, el('b', { text: alertTitle(a.kind, a.detail && a.detail.gateway) }), el('time', { text: fmtClock(a.time) })),
          el('p', { class: 'alert-text', text: alertText(a) + (a.confidence != null ? '  (' + t('guard.conf.' + (a.confidence >= 0.75 ? 'high' : a.confidence >= 0.45 ? 'medium' : 'low')) + ')' : '') }),
          (a.evidence && a.evidence.length) ? el('ul', { class: 'evidence', title: t('guard.evidence') }, ...a.evidence.slice(0, 5).map((line) => el('li', { text: line }))) : null,
          el('p', { class: 'alert-next', text: alertNextStep(a.kind) }),
          actions
        );
        alertEls.set(a.id, li);
      }
      return li;
    });
    list.replaceChildren(...rows);
    $('#alertEmpty').hidden = state.alerts.length > 0;
  }

  function addAlert(a) {
    state.alerts.push(a);
    if (state.alerts.length > 300) { const gone = state.alerts.shift(); alertEls.delete(gone.id); }
    if (a.severity === 'high') flashScreen();
    if (a.src_ip && a.kind !== 'baseline') scene.addAlarm(a.src_ip, a.severity);
    if (state.tab === 'guard') state.alertLast = state.alerts.length;
    renderAlertCount(); renderAlerts();
    toast(alertTitle(a.kind, a.detail && a.detail.gateway) + ': ' + alertText(a), a.severity === 'high' ? 'error' : undefined);
  }

  function focusAlertFor(ip) {
    const a = state.alerts.slice().reverse().find((x) => x.src_ip === ip);
    if (!a) return;
    setTab('guard');
    const li = alertEls.get(a.id);
    if (li) { li.classList.add('focus'); li.scrollIntoView({ block: 'center', behavior: 'smooth' }); setTimeout(() => li.classList.remove('focus'), 2200); }
  }

  function restoreAlarms() {
    state.alerts.forEach((a) => { if (a.src_ip && a.kind !== 'baseline') scene.addAlarm(a.src_ip, a.severity); });
  }

  function showOnMap(ip) {
    setTab('scan'); setTab('hosts');
    if (state.hosts.has(ip)) scene.select(ip);
    else toast(ip);
  }

  async function trustDevice(mac, li) {
    try {
      const res = await api('guard/trust', { method: 'POST', body: JSON.stringify({ mac }) });
      if (res.ok) { li.querySelector('.alert-actions').replaceChildren(el('span', { class: 'badge', text: t('guard.trusted') })); toast(t('guard.trusted')); }
    } catch (e) { /* offline: nothing more we can do here */ }
  }

  function renderBlockCommands(ip, data) {
    const parts = t('block.title', { ip: '\u0000' }).split('\u0000');
    $('#blockTitle').replaceChildren(document.createTextNode(parts[0] || ''), el('bdi', { text: ip }), document.createTextNode(parts[1] || ''));
    $('#blockNote').textContent = t('block.note');
    const body = $('#blockBody');
    if (data.error === 'protected') { body.replaceChildren(el('p', { text: t('block.protected') })); return; }
    if (data.error) { body.replaceChildren(el('p', { text: t('block.unsupported') })); return; }
    body.replaceChildren(...data.options.map((opt) => {
      const box = el('div', { class: 'cmd' }, el('b', { text: opt.name }));
      opt.commands.forEach((cmd) => {
        const code = el('code', { text: cmd });
        const copyBtn = el('button', { type: 'button', class: 'btn', text: t('block.copy') });
        copyBtn.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(cmd); toast(t('block.copied')); } catch (e) { /* clipboard unavailable */ }
        });
        box.append(el('div', { class: 'line' }, code, copyBtn));
      });
      if (opt.undo && opt.undo.length) box.append(el('div', { class: 'undo' }, document.createTextNode(t('block.undo')), el('code', { text: opt.undo[0] })));
      return box;
    }));
  }

  async function showBlockDialog(ip) {
    let data;
    try {
      const res = await api('guard/block?ip=' + encodeURIComponent(ip));
      data = await res.json();
    } catch (e) { data = { error: 'offline' }; }
    renderBlockCommands(ip, data);
    $('#blockDlg').showModal();
  }

  async function toggleGuard(on) {
    if (on) {
      try {
        const res = await api('guard/start', { method: 'POST', body: JSON.stringify({ interval: 45 }) });
        const data = await res.json();
        if (!res.ok) { $('#guardSwitch').checked = false; toast(data.error || t('guard.err'), 'error'); return; }
        Object.assign(state.guard, data);
        attachGuardStream();
      } catch (e) { $('#guardSwitch').checked = false; toast(t('guard.err'), 'error'); }
    } else {
      if (state.guardEs) { state.guardEs.close(); state.guardEs = null; }
      if (state.guardDemo) { state.guardDemo(); state.guardDemo = null; }
      state.guard.running = false;
      try { await api('guard/stop', { method: 'POST' }); } catch (e) { /* best effort */ }
    }
    renderGuardStatus();
  }

  function attachGuardStream() {
    if (!state.token || state.guardEs) return;
    const es = new EventSource('/api/guard/events?k=' + encodeURIComponent(state.token));
    state.guardEs = es;
    es.onmessage = (m) => {
      const a = safe(() => JSON.parse(m.data));
      if (!a) return;
      if (a.kind === 'baseline') state.guard.learning = false;
      addAlert(a); renderGuardStatus();
    };
  }

  function simulateIntrusion() {
    const now = Date.now() / 1000;
    let seq = state.alerts.length;
    const make = (kind, severity, ip, mac, detail) => ({ id: ++seq + 900000, time: now, kind, severity, src_ip: ip, mac: mac || null, detail: detail || {} });
    const script = [
      [800, make('tripwire', 'high', '10.0.0.66', null, { count: 1, ports: (state.guard.decoys[0] ? [state.guard.decoys[0]] : [2222]), sample: 'GET /admin HTTP/1.1' })],
      [2600, make('new_device', 'medium', '10.0.0.67', 'de:ad:be:ef:13:37', {})],
      [4400, make('arp_change', 'high', state.info && state.info.suggested_target ? state.info.suggested_target.replace('0/24', '1') : '10.0.0.1', null,
        { old_mac: 'a4:2b:b0:1c:9e:10', new_mac: 'de:ad:be:ef:13:37', gateway: true })]
    ];
    const timers = script.map(([ms, alert]) => setTimeout(() => addAlert(alert), ms));
    state.guardDemo = () => timers.forEach(clearTimeout);
    toast(t('guard.simulate'));
  }

  function toast(msg, kind) {
    const box = $('#toasts'), node = el('div', { class: 'toast' + (kind === 'error' ? ' error' : ''), text: msg });
    box.append(node);
    setTimeout(() => node.remove(), 3700);
  }

  function closeMenu() {
    $('#exportPop').hidden = true; $('#btnExport').setAttribute('aria-expanded', 'false');
    $('#langPop').hidden = true; $('#btnLang').setAttribute('aria-expanded', 'false');
  }

  function renderLegend() {
    $('#legend').replaceChildren(...Object.keys(C.CATEGORIES).map((k) => {
      const dot = el('i'); dot.style.setProperty('--c', C.CATEGORIES[k].color);
      return el('div', {}, dot, el('span', { text: t('legend.' + k) }));
    }));
  }

  function applyLang(lang) {
    I.setLang(lang);
    $('#langCur').textContent = I.names[I.lang];
    $$('#langPop a').forEach((a) => a.setAttribute('aria-current', String(a.dataset.lang === I.lang)));
    // the local-language brand name is Arabic for English and Arabic, Hebrew for Hebrew
    $$('.brand-ar, .ar-name').forEach((n) => { n.lang = I.lang === 'he' ? 'he' : 'ar'; });
    renderLegend(); renderStatus(); renderStats(); renderHosts(true); renderInspector(); renderLog(); updateInsets();
    renderGuardStatus(); alertEls.forEach((li, id) => { alertEls.delete(id); }); renderAlerts(); renderAlertCount();
    renderDiff();
  }

  function applyInfo() {
    const info = state.info;
    if (!info) return;
    const chip = $('#modeChip');
    chip.dataset.i18n = info.root ? 'mode.root' : 'mode.standard';
    chip.dataset.i18nTitle = info.root ? 'mode.root.tip' : 'mode.standard.tip';
    chip.classList.toggle('root', info.root);
    $('#chipNetVal').textContent = info.suggested_target;
    $('#quickSub').dataset.i18nVars = JSON.stringify({ n: info.top_ports });
    if (!$('#target').value) $('#target').value = info.suggested_target;
    I.apply(document);
    if (info.guard) {
      Object.assign(state.guard, info.guard);
      renderGuardStatus();
      if (info.guard.running) attachGuardStream();
    } else if (info.guard_ports) {
      state.guard.decoys = info.guard_ports;
    }
  }

  function bindUI() {
    $$('.tabs button').forEach((b) => b.addEventListener('click', () => setTab(b.dataset.tab)));
    $('#scanForm').addEventListener('submit', (e) => { e.preventDefault(); if (state.phase !== 'running') startScan(); });
    $('#btnStop').addEventListener('click', stopScan);
    $('#historyRefresh').addEventListener('click', loadHistory);
    $('#btnDemo').addEventListener('click', startDemo);
    $('#chipNet').addEventListener('click', () => { $('#target').value = (state.info && state.info.suggested_target) || '192.168.1.0/24'; });
    $('#chipSelf').addEventListener('click', () => { $('#target').value = '127.0.0.1'; });
    $$('input[name="depth"]').forEach((r) => r.addEventListener('change', () => {
      const custom = $('input[name="depth"]:checked').value === 'custom';
      $('#ports').hidden = !custom; if (custom) $('#ports').focus();
    }));
    $('#hostFilter').addEventListener('input', () => renderHosts(true));
    $('#btnLang').addEventListener('click', (e) => {
      e.stopPropagation();
      const pop = $('#langPop'), open = pop.hidden;
      closeMenu(); pop.hidden = !open;
      $('#btnLang').setAttribute('aria-expanded', String(open));
    });
    $$('#langPop a').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); closeMenu(); applyLang(a.dataset.lang); }));
    $('#btnLabels').addEventListener('click', (e) => {
      const on = e.currentTarget.getAttribute('aria-pressed') !== 'true';
      e.currentTarget.setAttribute('aria-pressed', String(on)); scene.setLabels(on);
    });
    $('#btnReset').addEventListener('click', () => { scene.select(null); scene.resetView(); });
    $('#inspClose').addEventListener('click', () => scene.select(null));
    $('#inspCopy').addEventListener('click', async () => {
      const h = state.hosts.get(state.selected); if (!h) return;
      const text = summary(h);
      try { await navigator.clipboard.writeText(text); } catch (e) {
        const ta = el('textarea', { style: 'position:fixed;opacity:0' }); ta.value = text; document.body.append(ta); ta.select(); document.execCommand('copy'); ta.remove();
      }
      toast(t('insp.copied'));
    });
    $('#btnExport').addEventListener('click', (e) => {
      e.stopPropagation();
      const pop = $('#exportPop'), open = pop.hidden;
      closeMenu(); pop.hidden = !open;
      $('#btnExport').setAttribute('aria-expanded', String(open));
    });
    $$('#exportPop a').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); download(a.dataset.fmt); }));
    document.addEventListener('click', (e) => { if (!e.target.closest('#exportMenu, #langMenu')) closeMenu(); });
    document.addEventListener('keydown', (e) => {
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || '');
      if (e.key === 'Escape') { closeMenu(); if (state.selected) scene.select(null); }
      else if (e.key === '/' && !typing) { e.preventDefault(); setTab('scan'); $('#target').focus(); }
    });
    $('#brand').addEventListener('click', (e) => { e.preventDefault(); scene.select(null); scene.resetView(); });
    $('#guardSwitch').addEventListener('change', (e) => toggleGuard(e.target.checked));
    $('#guardChip').addEventListener('click', () => setTab('guard'));
    $('#btnSimulate').addEventListener('click', simulateIntrusion);
    $('#blockClose').addEventListener('click', () => $('#blockDlg').close());
    $('#diffClose').addEventListener('click', () => { state.diff = null; renderDiff(); });
    window.addEventListener('resize', updateInsets);
    const layoutWatcher = new ResizeObserver(updateInsets);   // the legend changes with the language, the HUD with its wrapping
    ['#dock', '#legend', '#hud'].forEach((id) => layoutWatcher.observe($(id)));

    // panels lean gently toward the pointer
    if (!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches)) {
      $$('[data-tilt]').forEach((p) => {
        p.addEventListener('pointermove', (e) => {
          const b = p.getBoundingClientRect(), x = (e.clientX - b.left) / b.width, y = (e.clientY - b.top) / b.height;
          p.style.setProperty('--ry', ((x - 0.5) * (b.width > 500 ? 1.2 : 2.6)).toFixed(2) + 'deg');
          p.style.setProperty('--rx', (-(y - 0.5) * (b.height > 500 ? 1.0 : 2.2)).toFixed(2) + 'deg');
          p.style.setProperty('--mx', (x * 100).toFixed(0) + '%'); p.style.setProperty('--my', (y * 100).toFixed(0) + '%');
        });
        p.addEventListener('pointerleave', () => { p.style.setProperty('--rx', '0deg'); p.style.setProperty('--ry', '0deg'); });
      });
    }
  }

  function initSplash() {
    const splash = $('#splash');
    const seen = safe(() => sessionStorage.getItem('nemla.splash'));
    const reduced = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (seen || reduced) { splash.remove(); return; }
    let closed = false;
    const out = () => { if (closed) return; closed = true; splash.classList.add('out'); setTimeout(() => splash.remove(), 800); };
    safe(() => sessionStorage.setItem('nemla.splash', '1'));
    splash.addEventListener('click', out);
    document.addEventListener('keydown', out, { once: true });
    setTimeout(out, 2600);
  }

  /* ----------------------------------------------------------------- boot */

  async function boot() {
    bootToken();
    initScene();
    bindUI();
    initSplash();
    applyLang(I.detect(null));
    setTab('scan');
    updateInsets();
    if (state.token) {
      try {
        const res = await api('info');
        if (res.ok) {
          state.info = await res.json();
          const saved = safe(() => localStorage.getItem('nemla.lang'));
          if (state.info.lang && !saved) applyLang(state.info.lang);
          try {   // finding titles, explanations and fixes come from the server, in every language
            const texts = await api('strings');
            if (texts.ok) { I.extend(await texts.json()); I.apply(document); }
          } catch (e) { /* the built-in texts still work */ }
          applyInfo();
          startHeartbeat();
          if (state.info.job) attach(state.info.job.id);
        }
      } catch (e) { showLost('gone'); }
    }
    if (/[?&]demo=1/.test(location.search)) startDemo();
  }

  boot();
})();
