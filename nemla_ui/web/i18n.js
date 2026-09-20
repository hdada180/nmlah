/* Nemla UI strings: English, Arabic and Hebrew. Text is always inserted with textContent. */
(function () {
  'use strict';

  const RTL = { ar: true, he: true };
  const NAMES = { en: 'English', ar: 'العربية', he: 'עברית' };

  const STRINGS = {
    en: {
      'app.tagline': 'Discover · Scan · Fingerprint · Report',
      'brand.local': 'نملة',
      'lang.menu': 'Language',

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
      'scan.opt.banner': 'Identify services (versions, TLS, web titles)',
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
      'hud.findings': 'Findings',
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
      'insp.findings': 'Findings',
      'insp.nofindings': 'Nothing worrying found on this host.',
      'insp.noports': 'No open ports in the scanned range.',
      'insp.pending': 'Still scanning this host…',
      'insp.copy': 'Copy summary',
      'insp.copied': 'Copied to clipboard',
      'insp.close': 'Close',
      'insp.nobanner': 'no banner',
      'insp.cert': 'certificate',

      'sev.high': 'High',
      'sev.medium': 'Medium',
      'sev.low': 'Low',
      'sev.info': 'Info',

      'find.telnet': 'Telnet is open on port {port}: logins and data travel in clear text.',
      'find.ftp': 'FTP is open on port {port}: passwords are sent in clear text.',
      'find.remote': 'Remote access is reachable: {service} on port {port}.',
      'find.db': 'A database is reachable over the network: {service} on port {port}.',
      'find.files': 'File sharing is reachable: {service} on port {port}.',
      'find.redis_open': 'Redis answers without a password on port {port}.',
      'find.memcached': 'Memcached answers anyone on port {port}; it can be abused to amplify traffic.',
      'find.es_open': 'Elasticsearch answers without a login on port {port}.',
      'find.http_plain': 'A website is served over plain HTTP on port {port} and this host has no HTTPS.',
      'find.tls_expired': 'The TLS certificate on port {port} expired {days} day(s) ago.',
      'find.tls_expiring': 'The TLS certificate on port {port} expires in {days} day(s).',
      'find.tls_old': 'Port {port} still accepts an obsolete protocol ({version}).',
      'find.tls_selfsigned': 'The TLS certificate on port {port} is self-signed.',
      'find.version': '{product} {version} on port {port} announces its exact version to anyone who connects.',

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
      'toast.done': 'Scan finished: {hosts} host(s), {ports} open port(s), {findings} finding(s)',
      'toast.stopped': 'Scan stopped',
      'toast.nodemo': 'Open Nemla from its launcher to run real scans.',

      'demo.badge': 'DEMO',

      'boot.colony': 'Waking the colony',
      'boot.net': 'Checking network interfaces',
      'boot.trail': 'Laying the pheromone trail'
    },

    ar: {
      'app.tagline': 'اكتشاف · فحص · تخمين · تقرير',
      'brand.local': 'نملة',
      'lang.menu': 'اللغة',

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
      'scan.opt.banner': 'تحديد الخدمات (النسخ وTLS وعناوين المواقع)',
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
      'hud.findings': 'ملاحظات',
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
      'insp.findings': 'الملاحظات الأمنية',
      'insp.nofindings': 'ما لقينا شي مقلق على هالجهاز.',
      'insp.noports': 'لا توجد منافذ مفتوحة ضمن النطاق المفحوص.',
      'insp.pending': 'لسا بنفحص هذا الجهاز…',
      'insp.copy': 'نسخ الملخص',
      'insp.copied': 'تم النسخ',
      'insp.close': 'إغلاق',
      'insp.nobanner': 'بدون لافتة',
      'insp.cert': 'الشهادة',

      'sev.high': 'عالية',
      'sev.medium': 'متوسطة',
      'sev.low': 'منخفضة',
      'sev.info': 'معلومة',

      'find.telnet': 'Telnet مفتوح على المنفذ {port}: تسجيل الدخول والبيانات بتنبعت نص واضح بدون تشفير.',
      'find.ftp': 'FTP مفتوح على المنفذ {port}: كلمات السر بتنبعت نص واضح.',
      'find.remote': 'الوصول عن بُعد متاح: {service} على المنفذ {port}.',
      'find.db': 'قاعدة بيانات ظاهرة على الشبكة: {service} على المنفذ {port}.',
      'find.files': 'مشاركة الملفات ظاهرة: {service} على المنفذ {port}.',
      'find.redis_open': 'Redis بيرد بدون كلمة سر على المنفذ {port}.',
      'find.memcached': 'Memcached بيرد لأي حدا على المنفذ {port}، وممكن يُستغل لتضخيم الترافيك.',
      'find.es_open': 'Elasticsearch بيرد بدون تسجيل دخول على المنفذ {port}.',
      'find.http_plain': 'موقع شغّال على HTTP عادي بدون تشفير على المنفذ {port}، وما في HTTPS على هالجهاز.',
      'find.tls_expired': 'شهادة TLS على المنفذ {port} انتهت من {days} يوم.',
      'find.tls_expiring': 'شهادة TLS على المنفذ {port} بتنتهي بعد {days} يوم.',
      'find.tls_old': 'المنفذ {port} لسا بيقبل بروتوكول قديم ({version}).',
      'find.tls_selfsigned': 'شهادة TLS على المنفذ {port} موقّعة ذاتياً.',
      'find.version': '{product} {version} على المنفذ {port} بيعلن نسخته بالضبط لأي حدا بيتصل فيه.',

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
      'toast.done': 'انتهى الفحص: {hosts} جهاز، {ports} منفذ مفتوح، {findings} ملاحظة',
      'toast.stopped': 'تم إيقاف الفحص',
      'toast.nodemo': 'افتح نملة من مشغّلها لتنفيذ فحوصات حقيقية.',

      'demo.badge': 'تجريبي',

      'boot.colony': 'إيقاظ المستعمرة',
      'boot.net': 'فحص واجهات الشبكة',
      'boot.trail': 'رسم أثر الفيرمون'
    },

    he: {
      'app.tagline': 'גילוי · סריקה · זיהוי · דיווח',
      'brand.local': 'נמלה',
      'lang.menu': 'שפה',

      'status.ready': 'מוכנה',
      'status.running': 'סורקת',
      'status.done': 'הסריקה הושלמה',
      'status.stopped': 'נעצרה',
      'status.error': 'שגיאה',
      'status.demo': 'הדגמה',

      'mode.standard': 'מצב רגיל',
      'mode.root': 'מצב root',
      'mode.standard.tip': 'רצה ללא הרשאות root: ARP ו-ICMP גולמי כבויים, ונמלה משתמשת ב-ping וב-TCP במקומם. הפעילו עם sudo לגילוי מלא.',
      'mode.root.tip': 'רצה עם הרשאות root: גילוי ARP ו-ICMP גולמי זמינים.',

      'tab.scan': 'סריקה',
      'tab.hosts': 'מכשירים',
      'tab.log': 'עקבות',

      'scan.title': 'סריקה חדשה',
      'scan.target': 'יעד',
      'scan.target.ph': '192.168.1.0/24 · 10.0.0.5 · example.org',
      'scan.chip.network': 'הרשת שלי',
      'scan.chip.self': 'המחשב הזה',
      'scan.depth': 'עומק',
      'scan.depth.quick': 'מהיר',
      'scan.depth.quick.sub': '{n} פורטים נפוצים',
      'scan.depth.standard': 'רגיל',
      'scan.depth.standard.sub': 'פורטים 1–1024',
      'scan.depth.deep': 'מעמיק',
      'scan.depth.deep.sub': 'פורטים 1–10000',
      'scan.depth.custom': 'מותאם',
      'scan.depth.custom.sub': 'אתם בוחרים',
      'scan.ports.ph': '22,80,443 או 1-1000',
      'scan.opt.os': 'ניחוש מערכת ההפעלה',
      'scan.opt.banner': 'זיהוי שירותים (גרסאות, TLS, כותרות אתרים)',
      'scan.opt.noping': 'דילוג על ping (היעד חוסם אותו)',
      'scan.advanced': 'מתקדם',
      'scan.threads': 'תהליכונים',
      'scan.timeout': 'זמן קצוב (שנ׳)',
      'scan.start': 'התחלת סריקה',
      'scan.stop': 'עצירה',
      'scan.again': 'סריקה חדשה',
      'scan.notice': 'סרקו רק רשתות שבבעלותכם או שמותר לכם לבדוק.',
      'scan.demo': 'צפו במושבה לדוגמה',
      'scan.needtarget': 'הקלידו יעד קודם, למשל 192.168.1.0/24.',

      'hud.hosts': 'מכשירים',
      'hud.open': 'פורטים פתוחים',
      'hud.findings': 'ממצאים',
      'hud.time': 'זמן',
      'hint.idle': 'לחצו על התחלה כדי לשלוח את הנמלה הראשונה',
      'phase.idle': 'מוכנים כשאתם מוכנים',
      'phase.discovery': 'מחפשת מכשירים פעילים…',
      'phase.ports': 'סורקת פורטים ב-{ip}',
      'phase.done': 'הסתיים תוך {sec} שנ׳',
      'phase.stopped': 'נעצרה אחרי {sec} שנ׳ · תוצאות חלקיות',
      'phase.nohosts': 'לא נמצאו מכשירים פעילים. נסו "דילוג על ping".',
      'phase.error': 'הסריקה נעצרה עקב שגיאה',

      'hosts.empty': 'אין עדיין מכשירים. התחילו סריקה כדי לשלוח את הנמלה הראשונה.',
      'hosts.filter': 'סינון מכשירים…',
      'hosts.nomatch': 'אף מכשיר לא תואם לסינון.',
      'hosts.more': '+{n}',
      'log.empty': 'כאן יופיע מה שנמלה עושה.',

      'insp.host': 'מכשיר',
      'insp.os': 'ניחוש מערכת',
      'insp.via': 'זוהה באמצעות',
      'insp.mac': 'כתובת MAC',
      'insp.ports': 'פורטים פתוחים',
      'insp.findings': 'ממצאים',
      'insp.nofindings': 'לא נמצא משהו מדאיג במכשיר הזה.',
      'insp.noports': 'אין פורטים פתוחים בטווח שנסרק.',
      'insp.pending': 'עדיין סורקת את המכשיר הזה…',
      'insp.copy': 'העתקת סיכום',
      'insp.copied': 'הועתק ללוח',
      'insp.close': 'סגירה',
      'insp.nobanner': 'ללא באנר',
      'insp.cert': 'תעודה',

      'sev.high': 'גבוהה',
      'sev.medium': 'בינונית',
      'sev.low': 'נמוכה',
      'sev.info': 'מידע',

      'find.telnet': 'Telnet פתוח בפורט {port}: פרטי התחברות ונתונים עוברים בטקסט גלוי.',
      'find.ftp': 'FTP פתוח בפורט {port}: סיסמאות נשלחות בטקסט גלוי.',
      'find.remote': 'גישה מרחוק זמינה: {service} בפורט {port}.',
      'find.db': 'מסד נתונים נגיש ברשת: {service} בפורט {port}.',
      'find.files': 'שיתוף קבצים נגיש: {service} בפורט {port}.',
      'find.redis_open': 'Redis עונה ללא סיסמה בפורט {port}.',
      'find.memcached': 'Memcached עונה לכל מי שפונה אליו בפורט {port}; אפשר לנצל אותו להגברת תעבורה.',
      'find.es_open': 'Elasticsearch עונה ללא התחברות בפורט {port}.',
      'find.http_plain': 'אתר מוגש ב-HTTP רגיל בפורט {port} ואין HTTPS במכשיר הזה.',
      'find.tls_expired': 'תוקף תעודת ה-TLS בפורט {port} פג לפני {days} ימים.',
      'find.tls_expiring': 'תוקף תעודת ה-TLS בפורט {port} יפוג בעוד {days} ימים.',
      'find.tls_old': 'פורט {port} עדיין מקבל פרוטוקול מיושן ({version}).',
      'find.tls_selfsigned': 'תעודת ה-TLS בפורט {port} חתומה עצמית.',
      'find.version': '{product} {version} בפורט {port} מכריז על הגרסה המדויקת שלו לכל מי שמתחבר.',

      'top.labels': 'כתובות IP',
      'top.reset': 'איפוס תצוגה',
      'top.export': 'ייצוא',
      'export.html': 'דוח HTML',
      'export.json': 'נתוני JSON',
      'export.csv': 'טבלת CSV',

      'consent.title': 'לפני הסריקה הראשונה',
      'consent.body': 'נמלה בודקת את הכתובות שאתם נותנים לה. סריקת מערכות או רשתות שאינן בבעלותכם, ללא אישור, עלולה להיות בלתי חוקית. נמלה רק מגלה ומדווחת, ואינה מנצלת שום פרצה.',
      'consent.check': 'הרשת הזו בבעלותי או שיש לי אישור לבדוק אותה',
      'consent.ok': 'המשך',
      'consent.cancel': 'ביטול',

      'legend.web': 'אינטרנט',
      'legend.remote': 'גישה מרחוק',
      'legend.db': 'מסדי נתונים',
      'legend.mail': 'דואר',
      'legend.files': 'קבצים ו-RPC',
      'legend.other': 'אחר',

      'scene.hint': 'גררו לסיבוב · גללו לזום · לחצו על מכשיר',

      'err.session.title': 'הדף איבד את הקשר עם נמלה',
      'err.session.body': 'סגרו את החלון ופתחו את נמלה מחדש מתפריט היישומים או באמצעות הפקודה nemla.',
      'err.gone.title': 'נמלה נעצרה',
      'err.gone.body': 'שרת נמלה כבר לא פועל. פתחו את נמלה מחדש כדי להמשיך.',
      'err.generic': 'משהו השתבש',
      'toast.demo': 'מושבה לדוגמה: המכשירים האלה מומצאים.',
      'toast.done': 'הסריקה הסתיימה: {hosts} מכשירים, {ports} פורטים פתוחים, {findings} ממצאים',
      'toast.stopped': 'הסריקה נעצרה',
      'toast.nodemo': 'פתחו את נמלה מהמשגר שלה כדי להריץ סריקות אמיתיות.',

      'demo.badge': 'הדגמה',

      'boot.colony': 'מעירה את המושבה',
      'boot.net': 'בודקת ממשקי רשת',
      'boot.trail': 'מתווה את שביל הפרומונים'
    }
  };

  let lang = 'en';

  function t(key, vars) {
    let text = (STRINGS[lang] && STRINGS[lang][key]) || STRINGS.en[key] || key;
    if (vars) text = text.replace(/\{(\w+)\}/g, (m, k) => (k in vars && vars[k] != null ? vars[k] : m));
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
    html.dir = RTL[lang] ? 'rtl' : 'ltr';
    try { localStorage.setItem('nemla.lang', lang); } catch (e) { /* private mode */ }
    apply(document);
    return lang;
  }

  function detect(serverDefault) {
    let saved = null;
    try { saved = localStorage.getItem('nemla.lang'); } catch (e) { /* ignore */ }
    if (saved && STRINGS[saved]) return saved;
    if (serverDefault && STRINGS[serverDefault]) return serverDefault;
    const nav = (navigator.language || 'en').toLowerCase();
    if (nav.startsWith('ar')) return 'ar';
    if (nav.startsWith('he') || nav.startsWith('iw')) return 'he';
    return 'en';
  }

  window.NemlaI18n = {
    t, apply, setLang, detect, names: NAMES, codes: Object.keys(STRINGS),
    get lang() { return lang; }
  };
})();
