DISCOVER · SCAN · FINGERPRINT · REPORT

نملةNemla v1.0
أداة استطلاع شبكة شاملة بلغة Python: تكتشف الأجهزة الحيّة، تفحص منافذها، تخمّن نظام تشغيلها، ثم تُخرج كل ذلك في تقرير HTML عربي أنيق.

$ sudo python3 nemla.py -t 192.168.1.0/24
$ sudo python3 nemla.py -t 192.168.1.1-50 -p 1-1000
$ sudo python3 nemla.py -t 192.168.1.10 --top-ports
→ nemla_report.html
المشروع على GitHub
01
اكتشاف الأجهزة
فحص ARP عبر scapy للشبكة المحلية، مع رجوع تلقائي إلى ICMP و TCP عند غياب الصلاحيات.

02
فحص المنافذ
فحص متوازٍ بمئات الخيوط: أهم 39 منفذاً شائعاً أو أي نطاق تحدده، مع قراءة الـ Banner وتسمية الخدمة.

03
تخمين نظام التشغيل
استنتاج من قيمة TTL ثم تدقيقه بالمنافذ المفتوحة: RDP/SMB تعني Windows، وSSH تعني Linux.

04
تقرير HTML
ملف واحد بالعربية RTL فيه إحصائيات الفحص وبطاقة لكل جهاز مع جدول المنافذ والخدمات.

OPTIONS
-t, --target
الهدف: IP أو CIDR أو نطاق مثل 192.168.1.1-50
-p, --ports
المنافذ: 1-1000 أو 22,80,443
--top-ports
الاكتفاء بأهم المنافذ الشائعة
-o, --output
مسار تقرير HTML (الافتراضي nemla_report.html)
--no-os
تخطي تخمين نظام التشغيل
--threads
عدد الخيوط المتوازية (الافتراضي 150)
STACK
Python 3
scapy
socket
ThreadPoolExecutor
argparse
HTML report
تنبيه: استخدم الأداة فقط على شبكات تملك صلاحية صريحة لفحصها. بعض الميزات مثل ARP و ICMP تحتاج صلاحيات root.
