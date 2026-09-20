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
  const ipKey = (ip) => ip.split('.').reduce((a, b) => a * 256 + (+b || 0), 0);
  const safe = (fn) => { try { return fn(); } catch (e) { return null; } };

  const state = {
    token: null, info: null, phase: 'idle', demo: false, job: null, es: null, stopDemo: null,
    hosts: new Map(), openPorts: 0, startedAt: 0, timer: null, finalSeconds: null,
    selected: null, tab: 'scan', logs: [], stage: 'discovery',
    prog: { done: 0, total: 0, hostIndex: 0, hostTotal: 0, pdone: 0, ptotal: 0 }, focusIp: null, lostShown: false
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
      onSelect: (ip) => { state.selected = ip; renderInspector(); renderHosts(true); updateInsets(); },
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
    if (w <= 900) { top = Math.max(top, 130); if (state.selected) bottom = Math.max(bottom, $('#inspector').getBoundingClientRect().height + 12); }
    scene.setInsets(l, r, top, bottom);
    const root = document.documentElement.style;
    root.setProperty('--il', (w <= 900 ? 0 : l) + 'px'); root.setProperty('--ir', (w <= 900 ? 0 : r) + 'px');
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
    return 0.2 + 0.8 * (Math.max(0, p.hostIndex - 1) + (p.ptotal ? p.pdone / p.ptotal : 0)) / Math.max(1, p.hostTotal);
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
    $('#btnExport').disabled = !(state.phase === 'done' || state.phase === 'stopped') || state.demo || !state.job;
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
  const findingText = (f) => t('find.' + f.id, Object.assign({ port: f.port }, f.params || {}));
  function countFindings() {
    let n = 0, high = 0;
    state.hosts.forEach((h) => (h.findings || []).forEach((f) => { if (f.severity !== 'info') { n += 1; if (f.severity === 'high') high += 1; } }));
    return { n, high };
  }
  function applyRisk(h) { scene.setHostRisk(h.ip, riskOf(h)); }

  function renderHosts(force) {
    const list = $('#hostList');
    const q = $('#hostFilter').value.trim().toLowerCase();
    const hosts = Array.from(state.hosts.values()).sort((a, b) => ipKey(a.ip) - ipKey(b.ip)).filter((h) => {
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
    const lines = [h.ip + (h.os_guess ? ' - ' + h.os_guess : '')];
    h.open_ports.forEach((p) => {
      const product = [p.product, p.version].filter(Boolean).join(' ');
      lines.push('  ' + p.port + '/tcp  ' + p.service + (product ? '  ' + product : '') + (p.banner ? '  ' + p.banner : ''));
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
    badges.replaceChildren(...[h.os_guess].filter(Boolean).map((x) => el('span', { class: 'badge', text: x })));
    const kv = $('#inspKv'), rows = [];
    if (h.mac) rows.push(['insp.mac', h.mac]);
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
        const li = el('li', { 'data-sev': f.severity }, el('span', { class: 'sev-chip', text: t('sev.' + f.severity) }), el('span', { text: findingText(f) }));
        return li;
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
        const li = el('li', {}, el('div', { class: 'row' }, el('span', { class: 'pnum', text: p.port }), el('span', { class: 'psvc', text: p.service })),
          product ? el('span', { class: 'prod', text: product }) : null,
          metaBits.length ? el('span', { class: 'meta', text: metaBits.join(' | ') }) : null,
          el('code', { class: p.banner ? '' : 'none', text: p.banner || t('insp.nobanner') }));
        li.style.setProperty('--c', portsColor(p.port));
        return li;
      });
      if (!items.length) items.push(el('li', {}, el('code', { class: 'none', text: h.state === 'done' || state.phase !== 'running' ? t('insp.noports') : t('insp.pending') })));
      ul.replaceChildren(...items);
    }
    if (wasHidden) updateInsets();
  }

  /* --------------------------------------------------------------- events */

  function resetRun() {
    if (state.es) { state.es.close(); state.es = null; }
    if (state.stopDemo) { state.stopDemo(); state.stopDemo = null; }
    clearInterval(state.timer);
    state.hosts.clear(); hostEls.clear(); state.openPorts = 0; state.logs = []; state.finalSeconds = null;
    state.selected = null; state.focusIp = null; state.stage = 'discovery';
    state.prog = { done: 0, total: 0, hostIndex: 0, hostTotal: 0, pdone: 0, ptotal: 0 };
    scene.clear();
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
        h.state = 'scanning'; state.focusIp = ev.ip; state.prog.hostIndex = ev.index; state.prog.hostTotal = ev.total; state.prog.pdone = 0;
        scene.setHostState(ev.ip, 'scanning'); renderPhaseText(); dirty(); break;
      }
      case 'port': {
        const h = state.hosts.get(ev.ip); if (!h || h.open_ports.some((p) => p.port === ev.port)) break;
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
      no_banner: !$('#optBanner').checked, threads: +$('#optThreads').value || 150, timeout: +$('#optTimeout').value || 0.7,
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
    if (!state.job || state.demo) return;
    const a = el('a', { href: '/api/report?job=' + encodeURIComponent(state.job) + '&fmt=' + fmt + '&lang=' + I.lang + '&k=' + encodeURIComponent(state.token), download: '' });
    document.body.append(a); a.click(); a.remove();
    closeMenu();
  }

  /* ------------------------------------------------------------------- ui */

  function setTab(name) {
    state.tab = name;
    $$('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
    $$('.pane').forEach((p) => { p.hidden = p.id !== 'pane-' + name; });
    if (name === 'log') renderLog();
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
  }

  function bindUI() {
    $$('.tabs button').forEach((b) => b.addEventListener('click', () => setTab(b.dataset.tab)));
    $('#scanForm').addEventListener('submit', (e) => { e.preventDefault(); if (state.phase !== 'running') startScan(); });
    $('#btnStop').addEventListener('click', stopScan);
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
    window.addEventListener('resize', updateInsets);
    new ResizeObserver(updateInsets).observe($('#dock'));

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
