/* Nemla UI strings: English + Arabic. Text is always inserted with textContent. */
(function () {
  'use strict';

  const STRINGS = {
    en: {
      'app.tagline': 'Discover · Scan · Fingerprint · Report',
      'lang.switch': 'العربية',

      'status.ready': 'Ready',
      'status.running': 'Scanning',
      'status.done': 'Scan complete',
      'status.stopped': 'Stopped',
      'status.error': 'Error',
      'status.demo': 'Demo',

      'mode.standard': 'Standard mode',
      'mode.root': 'Root mode',
      'mode.standard.tip': 'Running without root: ARP and raw ICMP are off, Nemla uses ping + TCP instead. Start with sudo for full discovery.',
      'mode.root.tip': 'Running with root privileges: ARP discovery and raw ICMP are available.',

      'tab.scan': 'Scan',
      'tab.hosts': 'Hosts',
      'tab.log': 'Trail',

      'scan.title': 'New scan',
      'scan.target': 'Target',
      'scan.target.ph': '192.168.1.0/24 · 10.0.0.5 · example.org',
      'scan.chip.network': 'My network',
      'scan.chip.self': 'This computer',
      'scan.depth': 'Depth',
      'scan.depth.quick': 'Quick',
      'scan.depth.quick.sub': '{n} common ports',
      'scan.depth.standard': 'Standard',
      'scan.depth.standard.sub': 'Ports 1–1024',
      'scan.depth.deep': 'Deep',
      'scan.depth.deep.sub': 'Ports 1–10000',
      'scan.depth.custom': 'Custom',
      'scan.depth.custom.sub': 'You choose',
      'scan.ports.ph': '22,80,443 or 1-1000',
      'scan.opt.os': 'Guess the operating system',
      'scan.opt.banner': 'Read service banners',
      'scan.opt.noping': 'Skip ping (target blocks it)',
      'scan.advanced': 'Advanced',
      'scan.threads': 'Threads',
      'scan.timeout': 'Timeout (s)',
      'scan.start': 'Start scan',
      'scan.stop': 'Stop',
      'scan.again': 'New scan',
      'scan.notice': 'Only scan networks you own or are allowed to test.',
      'scan.demo': 'Watch a demo colony',
      'scan.needtarget': 'Type a target first, for example 192.168.1.0/24.',

      'hud.hosts': 'Hosts',
      'hud.open': 'Open ports',
      'hud.time': 'Elapsed',
      'hint.idle': 'Press Start to send out the first ant',
      'phase.idle': 'Ready when you are',
      'phase.discovery': 'Finding live hosts…',
      'phase.ports': 'Scanning ports on {ip}',
      'phase.done': 'Finished in {sec}s',
      'phase.stopped': 'Stopped after {sec}s · partial results',
      'phase.nohosts': 'No live hosts found. Try “Skip ping”.',
      'phase.error': 'The scan stopped with an error',

      'hosts.empty': 'No hosts yet. Start a scan to send out the first ant.',
      'hosts.filter': 'Filter hosts…',
      'hosts.nomatch': 'No host matches your filter.',
      'hosts.more': '+{n}',
      'log.empty': 'The trail will show what Nemla is doing.',

      'insp.host': 'Host',
      'insp.os': 'System guess',
      'insp.via': 'Found via',
      'insp.mac': 'MAC address',
      'insp.ports': 'Open ports',
      'insp.noports': 'No open ports in the scanned range.',
      'insp.pending': 'Still scanning this host…',
      'insp.copy': 'Copy summary',
      'insp.copied': 'Copied to clipboard',
      'insp.close': 'Close',
      'insp.nobanner': 'no banner',

      'top.labels': 'IP labels',
      'top.reset': 'Reset view',
      'top.export': 'Export',
      'export.html': 'HTML report',
      'export.json': 'JSON data',
      'export.csv': 'CSV table',

      'consent.title': 'Before your first scan',
      'consent.body': 'Nemla probes the addresses you give it. Scanning systems or networks you do not own, without permission, may be illegal. Nemla only discovers and reports; it never exploits anything.',
      'consent.check': 'I own this network or have permission to test it',
      'consent.ok': 'Continue',
      'consent.cancel': 'Cancel',

      'legend.web': 'Web',
      'legend.remote': 'Remote access',
      'legend.db': 'Database',
      'legend.mail': 'Mail',
      'legend.files': 'Files & RPC',
      'legend.other': 'Other',

      'scene.hint': 'Drag to orbit · scroll to zoom · click a host',

      'err.session.title': 'This page lost its link to Nemla',
      'err.session.body': 'Close this window and open Nemla again from your applications menu or with the nemla command.',
      'err.gone.title': 'Nemla stopped',
      'err.gone.body': 'The Nemla server is no longer running. Open Nemla again to continue.',
      'err.generic': 'Something went wrong',
      'toast.demo': 'Demo colony: these hosts are made up.',
      'toast.done': 'Scan finished: {hosts} host(s), {ports} open port(s)',
      'toast.stopped': 'Scan stopped',
      'toast.nodemo': 'Open Nemla from its launcher to run real scans.',

      'demo.badge': 'DEMO',

      'boot.colony': 'Waking the colony',
      'boot.net': 'Checking network interfaces',
      'boot.trail': 'Laying the pheromone trail'
    },

    ar: {
      'app.tagline': 'اكتشاف · فحص · تخمين · تقرير',
      'lang.switch': 'English',

      'status.ready': 'جاهزة',
      'status.running': 'جاري الفحص',
      'status.done': 'اكتمل الفحص',
      'status.stopped': 'تم الإيقاف',
      'status.error': 'خطأ',
      'status.demo': 'تجريبي',

      'mode.standard': 'الوضع العادي',
      'mode.root': 'وضع الجذر',
      'mode.standard.tip': 'شغّالة بدون صلاحيات الجذر: ARP و ICMP الخام مطفيين، ونملة بتستخدم ping و TCP بدالهم. شغّلها بـ sudo لاكتشاف كامل.',
      'mode.root.tip': 'شغّالة بصلاحيات الجذر: اكتشاف ARP و ICMP الخام متاحين.',

      'tab.scan': 'فحص',
      'tab.hosts': 'الأجهزة',
      'tab.log': 'الأثر',

      'scan.title': 'فحص جديد',
      'scan.target': 'الهدف',
      'scan.target.ph': '192.168.1.0/24 · 10.0.0.5 · example.org',
      'scan.chip.network': 'شبكتي',
      'scan.chip.self': 'هذا الجهاز',
      'scan.depth': 'العمق',
      'scan.depth.quick': 'سريع',
      'scan.depth.quick.sub': '{n} منفذ شائع',
      'scan.depth.standard': 'عادي',
      'scan.depth.standard.sub': 'المنافذ 1–1024',
      'scan.depth.deep': 'عميق',
      'scan.depth.deep.sub': 'المنافذ 1–10000',
      'scan.depth.custom': 'مخصص',
      'scan.depth.custom.sub': 'إنت بتختار',
      'scan.ports.ph': '22,80,443 أو 1-1000',
      'scan.opt.os': 'تخمين نظام التشغيل',
      'scan.opt.banner': 'قراءة لافتات الخدمات',
      'scan.opt.noping': 'تخطي ping (الهدف بيحجبه)',
      'scan.advanced': 'خيارات متقدمة',
      'scan.threads': 'الخيوط',
      'scan.timeout': 'المهلة (ث)',
      'scan.start': 'ابدأ الفحص',
      'scan.stop': 'إيقاف',
      'scan.again': 'فحص جديد',
      'scan.notice': 'افحص فقط الشبكات اللي بتملكها أو مسموح لك تختبرها.',
      'scan.demo': 'شاهد مستعمرة تجريبية',
      'scan.needtarget': 'اكتب هدف أولاً، مثلاً 192.168.1.0/24.',

      'hud.hosts': 'الأجهزة',
      'hud.open': 'منافذ مفتوحة',
      'hud.time': 'الزمن',
      'hint.idle': 'اضغط ابدأ لترسل أول نملة',
      'phase.idle': 'جاهزين متى ما بدك',
      'phase.discovery': 'البحث عن الأجهزة الشغّالة…',
      'phase.ports': 'فحص منافذ {ip}',
      'phase.done': 'انتهى خلال {sec} ث',
      'phase.stopped': 'توقف بعد {sec} ث · نتائج جزئية',
      'phase.nohosts': 'ما لقينا أجهزة شغّالة. جرّب «تخطي ping».',
      'phase.error': 'توقف الفحص بسبب خطأ',

      'hosts.empty': 'ما في أجهزة لسا. ابدأ فحصاً لترسل أول نملة.',
      'hosts.filter': 'تصفية الأجهزة…',
      'hosts.nomatch': 'ما في جهاز بيطابق التصفية.',
      'hosts.more': '+{n}',
      'log.empty': 'هون بيبين الأثر اللي بتعمله نملة.',

      'insp.host': 'جهاز',
      'insp.os': 'تخمين النظام',
      'insp.via': 'تم اكتشافه عبر',
      'insp.mac': 'عنوان MAC',
      'insp.ports': 'المنافذ المفتوحة',
      'insp.noports': 'لا توجد منافذ مفتوحة ضمن النطاق المفحوص.',
      'insp.pending': 'لسا بنفحص هذا الجهاز…',
      'insp.copy': 'نسخ الملخص',
      'insp.copied': 'تم النسخ',
      'insp.close': 'إغلاق',
      'insp.nobanner': 'بدون لافتة',

      'top.labels': 'عناوين IP',
      'top.reset': 'إعادة ضبط الزاوية',
      'top.export': 'تصدير',
      'export.html': 'تقرير HTML',
      'export.json': 'بيانات JSON',
      'export.csv': 'جدول CSV',

      'consent.title': 'قبل أول فحص',
      'consent.body': 'نملة بتفحص العناوين اللي بتعطيها إياها. فحص أنظمة أو شبكات ما بتملكها بدون إذن ممكن يكون مخالف للقانون. نملة بتكتشف وبتوثّق بس، وما بتستغل أي ثغرة.',
      'consent.check': 'أنا بملك هذه الشبكة أو عندي إذن باختبارها',
      'consent.ok': 'متابعة',
      'consent.cancel': 'إلغاء',

      'legend.web': 'ويب',
      'legend.remote': 'وصول عن بُعد',
      'legend.db': 'قواعد بيانات',
      'legend.mail': 'بريد',
      'legend.files': 'ملفات و RPC',
      'legend.other': 'أخرى',

      'scene.hint': 'اسحب للتدوير · مرّر للتقريب · اضغط على جهاز',

      'err.session.title': 'هذه الصفحة فقدت اتصالها بنملة',
      'err.session.body': 'سكّر هذه النافذة وافتح نملة من جديد من قائمة التطبيقات أو بأمر nemla.',
      'err.gone.title': 'توقفت نملة',
      'err.gone.body': 'خادم نملة ما عاد شغّال. افتح نملة من جديد للمتابعة.',
      'err.generic': 'صار خطأ ما',
      'toast.demo': 'مستعمرة تجريبية: هذه الأجهزة مختلقة.',
      'toast.done': 'انتهى الفحص: {hosts} جهاز، {ports} منفذ مفتوح',
      'toast.stopped': 'تم إيقاف الفحص',
      'toast.nodemo': 'افتح نملة من مشغّلها لتنفيذ فحوصات حقيقية.',

      'demo.badge': 'تجريبي',

      'boot.colony': 'إيقاظ المستعمرة',
      'boot.net': 'فحص واجهات الشبكة',
      'boot.trail': 'رسم أثر الفيرمون'
    }
  };

  let lang = 'en';

  function t(key, vars) {
    let text = (STRINGS[lang] && STRINGS[lang][key]) || STRINGS.en[key] || key;
    if (vars) text = text.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? vars[k] : m));
    return text;
  }

  function apply(root) {
    root = root || document;
    root.querySelectorAll('[data-i18n]').forEach((node) => {
      const vars = node.dataset.i18nVars ? JSON.parse(node.dataset.i18nVars) : undefined;
      node.textContent = t(node.dataset.i18n, vars);
    });
    root.querySelectorAll('[data-i18n-ph]').forEach((n) => { n.placeholder = t(n.dataset.i18nPh); });
    root.querySelectorAll('[data-i18n-title]').forEach((n) => { n.title = t(n.dataset.i18nTitle); });
    root.querySelectorAll('[data-i18n-aria]').forEach((n) => { n.setAttribute('aria-label', t(n.dataset.i18nAria)); });
  }

  function setLang(next) {
    lang = STRINGS[next] ? next : 'en';
    const html = document.documentElement;
    html.lang = lang;
    html.dir = lang === 'ar' ? 'rtl' : 'ltr';
    try { localStorage.setItem('nemla.lang', lang); } catch (e) { /* private mode */ }
    apply(document);
    return lang;
  }

  function detect(serverDefault) {
    let saved = null;
    try { saved = localStorage.getItem('nemla.lang'); } catch (e) { /* ignore */ }
    if (saved && STRINGS[saved]) return saved;
    if (serverDefault && STRINGS[serverDefault]) return serverDefault;
    return (navigator.language || 'en').toLowerCase().startsWith('ar') ? 'ar' : 'en';
  }

  window.NemlaI18n = { t, apply, setLang, detect, get lang() { return lang; } };
})();
