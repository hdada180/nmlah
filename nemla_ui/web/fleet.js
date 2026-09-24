/* Nemla Fleet page: the agents, jobs and audit trail of one controller.
   Everything that comes from an agent or from a scanned host is inserted with textContent, never as HTML. */
(function () {
  'use strict';

  const $ = (sel, root) => (root || document).querySelector(sel);
  const safe = (fn) => { try { return fn(); } catch (e) { return null; } };
  function el(tag, props) {
    const node = document.createElement(tag);
    Object.keys(props || {}).forEach((k) => {
      if (k === 'class') node.className = props[k];
      else if (k === 'text') node.textContent = props[k];
      else node.setAttribute(k, props[k]);
    });
    for (let i = 2; i < arguments.length; i++) {
      const kid = arguments[i];
      if (kid != null && kid !== false) node.append(kid);
    }
    return node;
  }

  /* ------------------------------------------------------------ text */

  const TEXT = {
    en: {
      title: 'Fleet', 'live.wait': 'Connecting', 'live.ok': 'Live', 'live.bad': 'No answer',
      lede: 'Networks you are authorized to scan, watched from one place. Each agent keeps its own scope; the controller can never widen it.',
      'stat.online': 'Online', 'stat.offline': 'Offline', 'stat.running': 'Running', 'stat.queued': 'Queued', 'stat.revoked': 'Revoked',
      'agents.title': 'Agents', 'agents.add': 'Add agent', 'agents.none': 'No agents yet. Add one to get started.',
      'col.name': 'Agent', 'col.status': 'Status', 'col.scope': 'Scope (set on the agent)', 'col.seen': 'Last seen', 'col.activity': 'Activity',
      'col.job': 'Job', 'col.target': 'Target', 'col.result': 'Result', 'col.when': 'Queued', 'col.ip': 'Address', 'col.os': 'System', 'col.ports': 'Open ports',
      'status.online': 'Online', 'status.offline': 'Offline', 'status.revoked': 'Revoked',
      'state.queued': 'Queued', 'state.sent': 'Sent', 'state.running': 'Running', 'state.done': 'Done', 'state.failed': 'Failed',
      'state.cancelled': 'Cancelled', 'state.expired': 'Expired',
      'act.scan': 'Scan', 'act.revoke': 'Revoke', 'act.sure': 'Sure? Revoke', 'act.view': 'View', 'act.cancel': 'Cancel job',
      idle: 'Idle', 'queued.n': '{n} queued', never: 'never', 'addr.n': '{n} addresses', hosts: '{h} hosts · {p} open ports',
      'jobs.title': 'Jobs', 'jobs.none': 'No jobs yet.',
      'audit.title': 'Audit trail', 'audit.note': 'Append-only. Secrets are never written to it.', 'audit.none': 'Nothing recorded yet.',
      close: 'Close', cancel: 'Cancel',
      'add.title': 'Add an agent',
      'add.intro': "Enrollment happens on the agent's own machine. This makes a one-time token; nothing is installed remotely.",
      'add.name': 'Agent name', 'add.scope': 'Scope this agent will be allowed to scan',
      'add.scopehint': 'Set on the agent, not here. Used only to fill in the command below.',
      'add.run': 'Run this on the machine that will do the scanning. The token works once and expires in 15 minutes.',
      'add.make': 'Create token', 'add.copy': 'Copy command', 'add.copied': 'Copied',
      'scan.title': 'Scan with {name}', 'scan.scope': 'This agent may only scan: {scope}',
      'scan.target': 'Target', 'scan.ports': 'TCP ports', 'scan.noos': 'Skip OS fingerprinting', 'scan.noping': 'Treat every address as up',
      'scan.hint': 'Addresses, CIDR blocks or ranges only. The agent checks this against its own scope and limits again before it scans.',
      'scan.go': 'Queue scan',
      'res.title': 'Scan of {target}', 'res.meta': '{agent} · {time}', 'res.none': 'No hosts answered.',
      'chg.first': 'First scan of this target', 'chg.none': 'No changes since the previous scan',
      'chg.new': '{n} new hosts', 'chg.gone': '{n} hosts gone', 'chg.open': '{n} ports opened', 'chg.closed': '{n} ports closed', 'chg.find': '{n} new findings',
      'tls.pinned': 'TLS', 'tls.none': 'No TLS: this machine only', 'pin.copy': 'Fingerprint', 'pin.copied': 'Fingerprint copied',
      listen: 'Agents connect to {addr}', 'agents.n': '{n} of {max} agents', 'err.generic': 'Something went wrong',
      'lost.session.title': 'This page is not signed in',
      'lost.session.body': 'Open the link printed by "nemla controller serve": it carries a private key in the address.',
      'lost.gone.title': 'The controller stopped answering',
      'lost.gone.body': 'It may have been stopped. Start it again with "nemla controller serve", then reload this page.'
    },
    ar: {
      title: 'الأسطول', 'live.wait': 'جارٍ الاتصال', 'live.ok': 'مباشر', 'live.bad': 'لا يوجد رد',
      lede: 'الشبكات المصرَّح لك بفحصها، تراقبها من مكان واحد. كل وكيل يحتفظ بنطاقه الخاص، ولا يستطيع المتحكم توسيعه أبدًا.',
      'stat.online': 'متصل', 'stat.offline': 'غير متصل', 'stat.running': 'قيد التنفيذ', 'stat.queued': 'في الانتظار', 'stat.revoked': 'ملغى',
      'agents.title': 'الوكلاء', 'agents.add': 'إضافة وكيل', 'agents.none': 'لا يوجد وكلاء بعد. أضف واحدًا للبدء.',
      'col.name': 'الوكيل', 'col.status': 'الحالة', 'col.scope': 'النطاق (يُحدَّد على الوكيل)', 'col.seen': 'آخر ظهور', 'col.activity': 'النشاط',
      'col.job': 'المهمة', 'col.target': 'الهدف', 'col.result': 'النتيجة', 'col.when': 'وقت الإضافة', 'col.ip': 'العنوان', 'col.os': 'النظام', 'col.ports': 'المنافذ المفتوحة',
      'status.online': 'متصل', 'status.offline': 'غير متصل', 'status.revoked': 'ملغى',
      'state.queued': 'في الانتظار', 'state.sent': 'أُرسلت', 'state.running': 'قيد التنفيذ', 'state.done': 'اكتملت', 'state.failed': 'فشلت',
      'state.cancelled': 'أُلغيت', 'state.expired': 'انتهت مهلتها',
      'act.scan': 'فحص', 'act.revoke': 'إلغاء الوكيل', 'act.sure': 'متأكد؟ إلغاء', 'act.view': 'عرض', 'act.cancel': 'إلغاء المهمة',
      idle: 'خامل', 'queued.n': '{n} في الانتظار', never: 'أبدًا', 'addr.n': '{n} عنوان', hosts: '{h} جهاز · {p} منفذ مفتوح',
      'jobs.title': 'المهام', 'jobs.none': 'لا توجد مهام بعد.',
      'audit.title': 'سجل التدقيق', 'audit.note': 'للإضافة فقط. لا تُكتب الأسرار فيه أبدًا.', 'audit.none': 'لم يُسجَّل شيء بعد.',
      close: 'إغلاق', cancel: 'إلغاء',
      'add.title': 'إضافة وكيل',
      'add.intro': 'التسجيل يتم على جهاز الوكيل نفسه. هذا ينشئ رمزًا لمرة واحدة؛ لا شيء يُثبَّت عن بُعد.',
      'add.name': 'اسم الوكيل', 'add.scope': 'النطاق المسموح لهذا الوكيل بفحصه',
      'add.scopehint': 'يُحدَّد على الوكيل وليس هنا. يُستخدم فقط لتعبئة الأمر أدناه.',
      'add.run': 'نفّذ هذا الأمر على الجهاز الذي سيقوم بالفحص. الرمز يعمل مرة واحدة وينتهي بعد 15 دقيقة.',
      'add.make': 'إنشاء الرمز', 'add.copy': 'نسخ الأمر', 'add.copied': 'تم النسخ',
      'scan.title': 'فحص عبر {name}', 'scan.scope': 'يُسمح لهذا الوكيل بفحص هذا النطاق فقط: {scope}',
      'scan.target': 'الهدف', 'scan.ports': 'منافذ TCP', 'scan.noos': 'تخطي تحديد نظام التشغيل', 'scan.noping': 'اعتبار كل عنوان متصلًا',
      'scan.hint': 'عناوين أو نطاقات CIDR أو مدى فقط. يتحقق الوكيل من هذا مرة أخرى مقابل نطاقه وحدوده قبل أن يفحص.',
      'scan.go': 'إضافة الفحص للطابور',
      'res.title': 'فحص {target}', 'res.meta': '{agent} · {time}', 'res.none': 'لم يردّ أي جهاز.',
      'chg.first': 'أول فحص لهذا الهدف', 'chg.none': 'لا تغييرات منذ الفحص السابق',
      'chg.new': '{n} أجهزة جديدة', 'chg.gone': '{n} أجهزة اختفت', 'chg.open': '{n} منافذ فُتحت', 'chg.closed': '{n} منافذ أُغلقت', 'chg.find': '{n} نتائج جديدة',
      'tls.pinned': 'TLS', 'tls.none': 'بدون TLS: هذا الجهاز فقط', 'pin.copy': 'البصمة', 'pin.copied': 'تم نسخ البصمة',
      listen: 'الوكلاء يتصلون بـ {addr}', 'agents.n': '{n} من {max} وكيل', 'err.generic': 'حدث خطأ ما',
      'lost.session.title': 'هذه الصفحة غير مسجَّلة الدخول',
      'lost.session.body': 'افتح الرابط الذي يطبعه الأمر "nemla controller serve": فهو يحمل مفتاحًا خاصًا في العنوان.',
      'lost.gone.title': 'توقف المتحكم عن الرد',
      'lost.gone.body': 'ربما أُوقف. شغّله من جديد بالأمر "nemla controller serve" ثم أعد تحميل الصفحة.'
    }
  };

  let lang = 'en';
  (function pickLanguage() {
    const saved = safe(() => localStorage.getItem('nemla.lang'));
    const guess = (saved || navigator.language || 'en').slice(0, 2).toLowerCase();
    lang = TEXT[guess] ? guess : 'en';
  })();

  function t(key, vars) {
    let s = (TEXT[lang] && TEXT[lang][key]) || TEXT.en[key] || key;
    Object.keys(vars || {}).forEach((k) => { s = s.split('{' + k + '}').join(String(vars[k])); });
    return s;
  }

  function applyLanguage() {
    const html = document.documentElement;
    html.lang = lang;
    html.dir = lang === 'ar' ? 'rtl' : 'ltr';
    document.title = 'Nemla ' + t('title');
    document.querySelectorAll('[data-i18n]').forEach((n) => { n.textContent = t(n.getAttribute('data-i18n')); });
    $('#btnLang').textContent = lang === 'ar' ? 'English' : 'العربية';
    safe(() => localStorage.setItem('nemla.lang', lang));
  }

  /* ----------------------------------------------------------- state */

  const state = { token: null, info: null, agents: [], jobs: [], audit: [], lost: false, misses: 0, timer: null, armed: null, armedAt: 0, sig: {} };
  const fmtWhen = (epoch) => (epoch ? new Date(epoch * 1000).toLocaleString(lang) : '');

  function ago(epoch) {
    if (!epoch) return t('never');
    const secs = Math.round(epoch - Date.now() / 1000);
    const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
    const abs = Math.abs(secs);
    if (abs < 60) return rtf.format(secs, 'second');
    if (abs < 3600) return rtf.format(Math.round(secs / 60), 'minute');
    if (abs < 86400) return rtf.format(Math.round(secs / 3600), 'hour');
    return rtf.format(Math.round(secs / 86400), 'day');
  }

  function bootToken() {
    const m = /[#&]k=([\w-]+)/.exec(location.hash);
    if (m) {
      state.token = m[1];
      safe(() => sessionStorage.setItem('nemla.fk', state.token));
      history.replaceState(null, '', location.pathname + location.search);
    } else {
      state.token = safe(() => sessionStorage.getItem('nemla.fk'));
    }
  }

  async function api(path, body) {
    const opts = { headers: { 'X-Nemla-Token': state.token || '', 'X-Nemla-Operator': 'web page' } };
    if (body !== undefined) {
      opts.method = 'POST';
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch('/api/fleet/' + path, opts);
    let data = {};
    try { data = await res.json(); } catch (e) { data = {}; }
    if (res.status === 401) showLost('session');
    return { ok: res.ok, status: res.status, data: data };
  }

  function showLost(kind) {
    state.lost = true;
    $('#lostTitle').textContent = t('lost.' + kind + '.title');
    $('#lostBody').textContent = t('lost.' + kind + '.body');
    $('#lost').hidden = false;
  }

  function setLive(kind) {
    $('#live').setAttribute('data-state', kind);
    $('#liveText').textContent = t(kind === 'ok' ? 'live.ok' : kind === 'bad' ? 'live.bad' : 'live.wait');
  }

  /* ---------------------------------------------------------- render */

  const stateChip = (kind, label) => el('span', { class: 'state ' + kind }, el('i'), el('span', { text: label }));

  function renderHead(row, keys, hideOnSmall) {
    row.replaceChildren(...keys.map((k) => el('th', { text: t(k), class: (hideOnSmall || []).includes(k) ? 'hide-s' : '' })));
  }

  function renderChips() {
    const info = state.info;
    if (!info) return;
    const chips = [];
    if (info.tls) {
      const pinBtn = el('button', { class: 'chip good', type: 'button', title: info.pin || '' },
        el('span', { text: t('tls.pinned') }), el('code', { text: (info.pin || '').replace('sha256:', '').slice(0, 16) + '…' }),
        el('span', { text: t('pin.copy') }));
      pinBtn.addEventListener('click', () => copyText(info.pin || '', pinBtn));
      chips.push(pinBtn);
    } else {
      chips.push(el('span', { class: 'chip warn', text: t('tls.none') }));
    }
    chips.push(el('span', { class: 'chip', text: t('listen', { addr: info.agent_listen }) }));
    chips.push(el('span', { class: 'chip', text: t('agents.n', { n: state.agents.filter((a) => !a.revoked).length, max: info.max_agents }) }));
    $('#chips').replaceChildren(...chips);
  }

  function renderStats() {
    const active = state.agents.filter((a) => !a.revoked);
    const count = (s) => state.jobs.filter((j) => j.state === s).length;
    const cards = [
      ['on', active.filter((a) => a.status === 'online').length, 'stat.online'],
      ['off', active.filter((a) => a.status !== 'online').length, 'stat.offline'],
      ['run', count('running') + count('sent'), 'stat.running'],
      ['', count('queued'), 'stat.queued'],
      ['rev', state.agents.length - active.length, 'stat.revoked']
    ];
    $('#stats').replaceChildren(...cards.map((c) => el('div', { class: 'stat ' + c[0] }, el('b', { text: String(c[1]) }), el('span', { text: t(c[2]) }))));
  }

  function agentRow(a) {
    const revoked = !!a.revoked;
    const status = revoked ? 'revoked' : a.status;
    const activity = a.running_job ? a.running_job : a.queued ? t('queued.n', { n: a.queued }) : t('idle');
    const name = el('td', { class: 'name' }, el('b', { text: a.name }),
      el('small', { class: 'mono', text: [a.hostname, a.agent_version && 'v' + a.agent_version].filter(Boolean).join(' · ') }));
    const scope = el('td', {}, el('span', { class: 'scope', text: a.scope || '' }), el('small', { class: 'dim', text: '  ' + t('addr.n', { n: a.scope_addresses || 0 }) }));
    const acts = el('td', { class: 'actions' });
    if (!revoked) {
      const scan = el('button', { class: 'btn small', type: 'button', text: t('act.scan') });
      scan.addEventListener('click', () => openScan(a));
      const armed = state.armed === a.name && Date.now() - state.armedAt < 4000;
      const rev = el('button', { class: 'btn small danger' + (armed ? ' armed' : ''), type: 'button', text: t(armed ? 'act.sure' : 'act.revoke') });
      rev.addEventListener('click', () => revoke(a));
      acts.append(scan, rev);
    }
    return el('tr', {}, name, el('td', {}, stateChip(status, t('status.' + status))), scope,
      el('td', revoked ? { class: 'dim hide-s' } : { class: 'dim hide-s', 'data-epoch': String(a.last_seen || 0), text: ago(a.last_seen) }),
      el('td', { class: 'mono dim', text: revoked ? '' : activity }), acts);
  }

  function renderAgents() {
    renderHead($('#agentsHead'), ['col.name', 'col.status', 'col.scope', 'col.seen', 'col.activity', ''], ['col.seen']);
    $('#agentsBody').replaceChildren(...state.agents.map(agentRow));
    $('#agentsEmpty').hidden = state.agents.length > 0;
    $('#agentsTable').hidden = state.agents.length === 0;
  }

  function changeChips(summary) {
    const c = summary && summary.changes;
    const out = [];
    if (!summary || !summary.hosts && summary.hosts !== 0) return out;
    if (c === null || c === undefined) return [el('span', { class: 'chip', text: t('chg.first') })];
    if (!c.changed) return [el('span', { class: 'chip good', text: t('chg.none') })];
    const add = (n, key, kind) => { if (n) out.push(el('span', { class: 'chip ' + kind, text: t(key, { n: n }) })); };
    add(c.new_hosts, 'chg.new', 'warn'); add(c.gone_hosts, 'chg.gone', ''); add(c.opened_ports, 'chg.open', 'warn');
    add(c.closed_ports, 'chg.closed', ''); add(c.new_findings, 'chg.find', 'bad');
    return out;
  }

  function jobRow(j) {
    const stateCell = el('td', {}, stateChip(j.state, t('state.' + j.state)));
    if (j.error && j.state !== 'done') stateCell.append(el('span', { class: 'err-line', text: j.error }));
    const s = j.summary;
    const result = el('td', { class: 'dim' });
    if (j.state === 'done' && s) {
      result.append(el('div', { text: t('hosts', { h: s.hosts, p: s.open_ports }) }));
      const chips = changeChips(s);
      if (chips.length) result.append(el('div', { class: 'chips' }, ...chips));
    }
    const acts = el('td', { class: 'actions' });
    if (j.state === 'done' && j.scan_id) {
      const view = el('button', { class: 'btn small', type: 'button', text: t('act.view') });
      view.addEventListener('click', () => openResult(j));
      acts.append(view);
    }
    if (['queued', 'sent', 'running'].includes(j.state)) {
      const stop = el('button', { class: 'btn small danger', type: 'button', text: t('act.cancel') });
      stop.addEventListener('click', () => cancelJob(j, stop));
      acts.append(stop);
    }
    return el('tr', {}, el('td', { class: 'mono', text: j.id }), el('td', { text: j.agent }), stateCell,
      el('td', {}, el('span', { class: 'scope', text: j.target }), el('small', { class: 'dim mono', text: '  ' + j.ports })),
      result, el('td', { class: 'dim hide-s', 'data-epoch': String(j.created || 0), text: ago(j.created) }), acts);
  }

  function renderJobs() {
    renderHead($('#jobsHead'), ['col.job', 'col.name', 'col.status', 'col.target', 'col.result', 'col.when', ''], ['col.when']);
    $('#jobsBody').replaceChildren(...state.jobs.map(jobRow));
    $('#jobsEmpty').hidden = state.jobs.length > 0;
    $('#jobsTable').hidden = state.jobs.length === 0;
  }

  function renderAudit() {
    const events = state.audit.slice().reverse();
    $('#auditList').replaceChildren(...events.map((e) => {
      const rest = Object.keys(e).filter((k) => !['time', 'epoch', 'event'].includes(k))
        .map((k) => k + '=' + (typeof e[k] === 'object' ? JSON.stringify(e[k]) : String(e[k]))).join('  ');
      const bad = /refused|failed|revoke|mismatch/.test(e.event);
      return el('li', {}, el('time', { text: fmtWhen(e.epoch) }), el('span', { class: 'ev' + (bad ? ' bad' : ''), text: e.event }),
        el('span', { class: 'detail', text: rest }));
    }));
    $('#auditEmpty').hidden = events.length > 0;
  }

  // A section is rebuilt only when its data changed: rebuilding rows under the pointer every few seconds would swallow clicks.
  function once(name, value, draw) {
    const key = JSON.stringify(value);
    if (state.sig[name] === key) return;
    state.sig[name] = key;
    draw();
  }

  function tickTimes() {
    document.querySelectorAll('[data-epoch]').forEach((n) => { n.textContent = ago(Number(n.getAttribute('data-epoch'))); });
  }

  function renderAll() {
    once('chips', [state.info, state.agents.filter((a) => !a.revoked).length], renderChips);
    once('stats', [state.agents.map((a) => [a.id, a.status, a.revoked]), state.jobs.map((j) => [j.id, j.state])], renderStats);
    once('agents', state.agents.map((a) => Object.assign({}, a, { last_seen: a.last_seen !== null })), renderAgents);
    once('jobs', state.jobs, renderJobs);
    once('audit', [state.audit.length, state.audit.length ? state.audit[state.audit.length - 1].epoch : 0], renderAudit);
    tickTimes();
  }

  /* --------------------------------------------------------- refresh */

  async function refresh() {
    if (state.lost) return;
    try {
      const calls = [api('agents'), api('jobs?limit=60'), api('audit?limit=80')];
      if (!state.info) calls.push(api('info'));
      const [agents, jobs, audit, info] = await Promise.all(calls);
      if (state.lost) return;
      if (!agents.ok || !jobs.ok || !audit.ok) throw new Error('bad answer');
      state.agents = agents.data.agents || [];
      state.jobs = jobs.data.jobs || [];
      state.audit = audit.data.events || [];
      if (info && info.ok) state.info = info.data;
      state.misses = 0;
      setLive('ok');
      renderAll();
    } catch (e) {
      state.misses += 1;
      setLive('bad');
      if (state.misses >= 3) showLost('gone');
    }
  }

  function loop() {
    clearTimeout(state.timer);
    state.timer = setTimeout(async () => {
      if (!document.hidden) await refresh();
      loop();
    }, 3000);
  }

  /* --------------------------------------------------------- actions */

  async function copyText(text, button) {
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = t(button.id === 'addCopy' ? 'add.copied' : 'pin.copied');
      setTimeout(() => { button.textContent = original; }, 1500);
    } catch (e) { /* the text is selectable on the page as well */ }
  }

  function revoke(agent) {
    if (state.armed === agent.name && Date.now() - state.armedAt < 4000) {
      state.armed = null;
      api('revoke', { agent: agent.name }).then(refresh);
    } else {
      state.armed = agent.name; state.armedAt = Date.now();
      renderAgents();
      setTimeout(renderAgents, 4100);
    }
  }

  function cancelJob(job, button) {
    button.disabled = true;
    api('cancel', { job: job.id }).then(refresh);
  }

  const problem = (res) => (res.data && res.data.error) || t('err.generic');

  /* add agent dialog */

  function controllerUrl() {
    const listen = (state.info && state.info.agent_listen) || '';
    const cut = listen.lastIndexOf(':');
    const host = listen.slice(0, cut), port = listen.slice(cut + 1);
    const wildcard = ['0.0.0.0', '::', '[::]', ''].includes(host);
    const shown = wildcard ? '<controller-host>' : host.includes(':') && !host.startsWith('[') ? '[' + host + ']' : host;
    return (state.info && state.info.tls ? 'https://' : 'http://') + shown + ':' + port;
  }

  function enrollCommand(token, scope) {
    const quoted = /^[\w./:,%-]+$/.test(scope) ? scope : '"' + scope.replace(/"/g, '') + '"';
    const pin = state.info && state.info.tls && state.info.pin ? ' --pin ' + state.info.pin : '';
    return 'nemla agent enroll ' + controllerUrl() + ' --token ' + token + ' --scope ' + (scope ? quoted : '<SCOPE>') + pin;
  }

  function openAdd() {
    $('#addName').value = ''; $('#addScope').value = '';
    $('#addError').hidden = true; $('#addResult').hidden = true; $('#addCopy').hidden = true;
    $('#addMake').hidden = false; $('#addName').disabled = false;
    $('#dlgAdd').showModal();
    $('#addName').focus();
  }

  async function makeToken(ev) {
    ev.preventDefault();
    const name = $('#addName').value.trim();
    const res = await api('enroll-token', { name: name });
    if (!res.ok) { $('#addError').textContent = problem(res); $('#addError').hidden = false; return; }
    $('#addError').hidden = true;
    $('#addCmd').textContent = enrollCommand(res.data.token, $('#addScope').value.trim());
    $('#addResult').hidden = false; $('#addCopy').hidden = false; $('#addMake').hidden = true;
    $('#addName').disabled = true;
    refresh();
  }

  /* scan dialog */

  let scanFor = null;

  function openScan(agent) {
    scanFor = agent;
    $('#scanTitle').textContent = t('scan.title', { name: agent.name });
    $('#scanScope').textContent = t('scan.scope', { scope: agent.scope });
    $('#scanTarget').value = ''; $('#scanError').hidden = true;
    $('#dlgScan').showModal();
    $('#scanTarget').focus();
  }

  async function sendScan(ev) {
    ev.preventDefault();
    const options = {};
    if ($('#scanNoOs').checked) options.no_os = true;
    if ($('#scanNoPing').checked) options.no_ping = true;
    const job = { target: $('#scanTarget').value.trim(), ports: $('#scanPorts').value.trim() || '1-1024', options: options };
    const res = await api('dispatch', { agent: scanFor.name, job: job });
    if (!res.ok) { $('#scanError').textContent = problem(res); $('#scanError').hidden = false; return; }
    $('#dlgScan').close();
    refresh();
  }

  /* result dialog */

  async function openResult(job) {
    const res = await api('result?agent=' + encodeURIComponent(job.agent_id) + '&id=' + encodeURIComponent(job.scan_id));
    if (!res.ok) return;
    const data = res.data;
    $('#resTitle').textContent = t('res.title', { target: data.target || job.target });
    $('#resMeta').textContent = t('res.meta', { agent: job.agent, time: data.scan_time || '' });
    $('#resChanges').replaceChildren(...changeChips(job.summary));
    renderHead($('#resHead'), ['col.ip', 'col.os', 'col.ports']);
    const hosts = Array.isArray(data.hosts) ? data.hosts : [];
    $('#resBody').replaceChildren(...hosts.slice(0, 500).map((h) => {
      const ports = (h.open_ports || []).slice(0, 200).map((p) => {
        const label = p.port + (p.proto && p.proto !== 'tcp' ? '/' + p.proto : '') + (p.service ? ' ' + p.service : '');
        return el('span', { class: 'chip', text: label });
      });
      return el('tr', {}, el('td', { class: 'mono', text: String(h.ip) }), el('td', { class: 'dim', text: String(h.os_guess || '') }),
        el('td', {}, el('div', { class: 'chips' }, ...ports)));
    }));
    $('#resEmpty').hidden = hosts.length > 0;
    $('#dlgResult').showModal();
  }

  /* ------------------------------------------------------------ boot */

  function wire() {
    $('#btnAdd').addEventListener('click', openAdd);
    $('#addClose').addEventListener('click', () => $('#dlgAdd').close());
    $('#addCopy').addEventListener('click', (e) => copyText($('#addCmd').textContent, e.currentTarget));
    $('#formAdd').addEventListener('submit', makeToken);
    $('#dlgAdd').addEventListener('close', () => { $('#addCmd').textContent = ''; });      // the token is not kept around
    $('#scanClose').addEventListener('click', () => $('#dlgScan').close());
    $('#formScan').addEventListener('submit', sendScan);
    $('#resClose').addEventListener('click', () => $('#dlgResult').close());
    $('#btnLang').addEventListener('click', () => { lang = lang === 'ar' ? 'en' : 'ar'; applyLanguage(); state.sig = {}; renderAll(); });
    setInterval(tickTimes, 1000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  }

  bootToken();
  applyLanguage();
  wire();
  if (!state.token) {
    showLost('session');
  } else {
    setLive('idle');
    refresh();
    loop();
  }
})();
