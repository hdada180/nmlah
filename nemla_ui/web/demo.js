/* A made-up colony that replays the same events a real scan produces,
   so the interface can be explored without touching any network. */
(function () {
  'use strict';

  const SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCBind',
    135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 587: 'SMTP-Submission',
    993: 'IMAPS', 1433: 'MSSQL', 2049: 'NFS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB'
  };
  const SSH = 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13';
  const NGINX = 'HTTP/1.1 200 OK | Server: nginx/1.24.0';
  const APACHE = 'HTTP/1.1 200 OK | Server: Apache/2.4.58 (Debian)';
  const LINUX = 'Linux / Unix / macOS (TTL=64)', UBUNTU = 'Ubuntu Linux (TTL=64)';
  const WIN = 'Windows (TTL=128)', WIN_RDP = 'Windows (RDP/SMB detected) (TTL=128)', NET = 'Network device (Cisco/Solaris) (TTL=255)';

  const P = (n, banner, extra) => Object.assign({ port: n, service: SERVICES[n] || 'unknown', banner: banner || '' }, extra || {});
  const OPENSSH = { product: 'OpenSSH', version: '9.6p1', os_hint: 'Ubuntu Linux' };
  const NGX = { product: 'nginx', version: '1.24.0', status: 200 };
  const TLS_OK = { version: 'TLSv1.3', subject: 'app.lab.local', issuer: "Let's Encrypt", not_after: '2027-04-02', days_left: 194, self_signed: false };
  const F = (id, severity, port, params) => ({ id: id, severity: severity, port: port || null, params: params || {} });
  const VER = (port, product, version) => F('version', 'info', port, { product: product, version: version });
  // the real scan names the maker of well-known prefixes; the demo mirrors the two it uses
  const vendorOf = (mac) => {
    const hex = (mac || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
    if (hex.startsWith('525400')) return 'QEMU/KVM (libvirt)';
    if (/^(B827EB|DCA632|D83ADD|E45F01)/.test(hex)) return 'Raspberry Pi Foundation';
    return null;
  };
  const H = (last, os, ports, mac, findings) => ({
    ip: '192.168.1.' + last, os_guess: os, ttl: /TTL=(\d+)/.test(os) ? +/TTL=(\d+)/.exec(os)[1] : null,
    mac: mac || null, vendor: vendorOf(mac), discovery: 'ARP', open_ports: ports, findings: findings || []
  });

  const HOSTS = [
    H(1, NET, [P(53), P(80, 'HTTP/1.1 200 OK | Server: lighttpd/1.4.59', { product: 'lighttpd', version: '1.4.59', status: 200, title: 'Home Router' }),
      P(443, '', { product: 'lighttpd', tls: { version: 'TLSv1.2', subject: 'router.lan', issuer: 'router.lan', not_after: '2035-01-01', days_left: 3200, self_signed: true } })], 'a4:2b:b0:1c:9e:10',
    [F('tls_selfsigned', 'low', 443), VER(80, 'lighttpd', '1.4.59')]),
    H(4, UBUNTU, [P(22, SSH, OPENSSH), P(80, NGINX, Object.assign({ title: 'Company Portal' }, NGX)),
      P(443, '', Object.assign({ tls: TLS_OK, title: 'Company Portal' }, NGX)), P(3306, '', { product: 'MySQL', version: '8.0.35' }),
      P(6379, '', { product: 'Redis', version: '7.0.11', auth: 'none' })], 'dc:a6:32:5e:11:07',
    [F('redis_open', 'high', 6379), F('db', 'medium', 3306, { service: 'MySQL' }), VER(22, 'OpenSSH', '9.6p1'), VER(80, 'nginx', '1.24.0')]),
    H(7, WIN_RDP, [P(135), P(139), P(445), P(3389)], '3c:52:82:aa:04:9d',
    [F('remote', 'medium', 3389, { service: 'RDP' }), F('files', 'low', 445, { service: 'SMB' }), F('files', 'low', 139, { service: 'NetBIOS' }), F('files', 'low', 135, { service: 'MS-RPC' })]),
    H(9, LINUX, [], 'f0:18:98:4d:c2:31'),
    H(12, UBUNTU, [P(22, SSH, OPENSSH), P(2049), P(111), P(445), P(139), P(8080, APACHE, { product: 'Apache httpd', version: '2.4.58', status: 200, title: 'NAS Login', os_hint: 'Debian Linux' })], 'b8:27:eb:73:5a:2c',
    [F('files', 'low', 2049, { service: 'NFS' }), F('files', 'low', 445, { service: 'SMB' }), F('http_plain', 'low', 8080)]),
    H(15, WIN, [P(135), P(445)], '00:1a:79:6c:31:be', [F('files', 'low', 445, { service: 'SMB' }), F('files', 'low', 135, { service: 'MS-RPC' })]),
    H(18, LINUX, [P(80, 'HTTP/1.1 200 OK | Server: Boa/0.94.14rc21', { product: 'Boa', version: '0.94.14rc21', status: 200, title: 'IP Camera' }), P(23, 'login:')], '9c:b6:d0:0e:88:41',
    [F('telnet', 'high', 23), F('http_plain', 'low', 80)]),
    H(21, UBUNTU, [P(22, SSH, OPENSSH), P(25, '220 mail.lab.local ESMTP Postfix (Ubuntu)', { product: 'Postfix', os_hint: 'Ubuntu Linux' }), P(587),
      P(993, '', { product: 'Dovecot', tls: { version: 'TLSv1.2', subject: 'mail.lab.local', issuer: 'mail.lab.local CA', not_after: '2026-10-02', days_left: 12, self_signed: false } }), P(143, '', { product: 'Dovecot' })], '52:54:00:ab:31:c7',
    [F('tls_expiring', 'medium', 993, { days: 12 }), VER(22, 'OpenSSH', '9.6p1')]),
    H(23, LINUX, [], '8c:85:90:3a:70:11'),
    H(26, UBUNTU, [P(22, SSH, OPENSSH), P(5432, '', { product: 'PostgreSQL' }), P(9200, 'HTTP/1.1 200 OK', { product: 'Elasticsearch', version: '8.11.0', status: 200, auth: 'none' })], '52:54:00:1e:9f:02',
    [F('es_open', 'high', 9200), F('db', 'medium', 5432, { service: 'PostgreSQL' })]),
    H(30, WIN, [P(135), P(139), P(445), P(1433, '', { product: 'Microsoft SQL Server' })], 'a0:36:9f:12:cb:84',
    [F('db', 'medium', 1433, { service: 'MSSQL' }), F('files', 'low', 445, { service: 'SMB' }), F('files', 'low', 139, { service: 'NetBIOS' }), F('files', 'low', 135, { service: 'MS-RPC' })]),
    H(33, LINUX, [P(5900, 'RFB 003.008', { product: 'VNC (RFB)', version: '003.008' })], '68:54:5a:4e:0d:f3',
    [F('remote', 'medium', 5900, { service: 'VNC' })]),
    H(38, UBUNTU, [P(22, SSH, OPENSSH), P(80, NGINX, NGX), P(443, '', Object.assign({ tls: TLS_OK }, NGX)), P(8443, '', { tls: { version: 'TLSv1.3', subject: 'admin.lab.local', issuer: 'admin.lab.local', not_after: '2030-05-01', days_left: 1300, self_signed: true } })], '52:54:00:66:c2:d8',
    [F('tls_selfsigned', 'low', 8443), VER(80, 'nginx', '1.24.0')]),
    H(41, LINUX, [], 'e4:5f:01:88:aa:65'),
    H(46, WIN_RDP, [P(135), P(139), P(445), P(3389)], '00:0c:29:f4:8b:1a',
    [F('remote', 'medium', 3389, { service: 'RDP' }), F('files', 'low', 445, { service: 'SMB' }), F('files', 'low', 139, { service: 'NetBIOS' }), F('files', 'low', 135, { service: 'MS-RPC' })]),
    H(52, UBUNTU, [P(22, SSH, OPENSSH), P(27017, '', { product: 'MongoDB' }), P(6379, '', { product: 'Redis', version: '6.2.6', auth: 'none' })], '52:54:00:d0:47:9c',
    [F('redis_open', 'high', 6379), F('db', 'medium', 27017, { service: 'MongoDB' })]),
    H(58, LINUX, [P(80, 'HTTP/1.1 401 Unauthorized | Server: Router-httpd', { product: 'Router-httpd', status: 401, title: 'Printer Setup' })], '14:cc:20:9b:3e:75',
    [F('http_plain', 'low', 80)]),
    H(63, LINUX, [], '44:d9:e7:ab:12:0f'),
    H(70, UBUNTU, [P(21, '220 (vsFTPd 3.0.5)', { product: 'vsftpd', version: '3.0.5' }), P(22, SSH, OPENSSH), P(80, APACHE, { product: 'Apache httpd', version: '2.4.58', status: 200, title: 'Index of /' })], '52:54:00:73:e1:5b',
    [F('ftp', 'medium', 21), F('http_plain', 'low', 80), VER(21, 'vsftpd', '3.0.5')]),
    H(77, WIN, [P(445)], '2c:f0:5d:31:6a:c9', [F('files', 'low', 445, { service: 'SMB' })]),
    H(84, LINUX, [P(22, 'SSH-2.0-dropbear_2022.83', { product: 'Dropbear', version: '2022.83' })], 'b0:be:76:15:d4:88', [VER(22, 'Dropbear', '2022.83')]),
    H(91, UBUNTU, [P(22, SSH, OPENSSH), P(80, NGINX, NGX), P(443, '', Object.assign({ tls: { version: 'TLSv1', subject: 'legacy.lab.local', issuer: 'legacy.lab.local CA', not_after: '2027-01-01', days_left: 100, self_signed: false } }, NGX)),
      P(3306, '', { product: 'MariaDB', version: '10.6.12' }), P(9200, 'HTTP/1.1 200 OK', { product: 'Elasticsearch', version: '7.17.9', status: 401, auth: 'required' })], '52:54:00:0b:c6:e4',
    [F('tls_old', 'medium', 443, { version: 'TLSv1' }), F('db', 'medium', 3306, { service: 'MySQL' }), F('db', 'medium', 9200, { service: 'Elasticsearch' })]),
    H(120, LINUX, [], '7c:2f:80:f8:29:d0'),
    H(200, UBUNTU, [P(22, SSH, OPENSSH), P(8080, 'HTTP/1.1 200 OK | Server: Jetty(9.4.51)', { product: 'Jetty', version: '9.4.51', status: 200, title: 'Jenkins' })], '52:54:00:c9:1d:6e',
    [F('http_plain', 'low', 8080), VER(22, 'OpenSSH', '9.6p1')])
  ];

  function shuffled(list) {
    const a = list.slice();
    for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
    return a;
  }

  function run(emit) {
    const timers = [];
    const at = (ms, fn) => { timers.push(setTimeout(fn, ms)); };
    const started = Date.now();
    const total = HOSTS.length;
    const found = shuffled(HOSTS);
    const DISCOVERY_MS = 3400;

    emit({ type: 'start', job: 'demo', target: '192.168.1.0/24', addresses: 254, ports: 38, started: started / 1000 });
    emit({ type: 'phase', phase: 'discovery', total: 254 });
    emit({ type: 'log', msg: 'Discovering hosts via ARP (254 addresses)...' });

    for (let i = 1; i <= 24; i++) {
      at((DISCOVERY_MS / 24) * i, () => emit({ type: 'progress', phase: 'discovery', done: Math.round(254 * i / 24), total: 254 }));
    }
    found.forEach((h, i) => {
      at(300 + (DISCOVERY_MS - 500) * (i / total) + Math.random() * 90,
        () => emit({ type: 'host', ip: h.ip, mac: h.mac, method: h.discovery }));
    });
    at(DISCOVERY_MS + 100, () => {
      emit({ type: 'log', msg: 'Discovered ' + total + ' host(s)' });
      emit({ type: 'log', msg: 'Scanning 38 port(s) per host' });
      emit({ type: 'phase', phase: 'ports', total: total, ports: 38 });
    });

    let clock = DISCOVERY_MS + 350;
    HOSTS.forEach((h, idx) => {
      const span = 380 + h.open_ports.length * 70;
      const t0 = clock;
      at(t0, () => {
        emit({ type: 'host_start', ip: h.ip, index: idx + 1, total: total });
        emit({ type: 'log', msg: 'Scanning ' + h.ip + ' ...' });
      });
      for (let k = 1; k <= 4; k++) {
        at(t0 + (span * 0.8 * k) / 4, () => emit({ type: 'progress', phase: 'ports', ip: h.ip, done: Math.round(38 * k / 4), total: 38 }));
      }
      h.open_ports.forEach((p, k) => {
        at(t0 + 120 + ((span - 200) * (k + 1)) / (h.open_ports.length + 1),
          () => emit(Object.assign({ type: 'port', ip: h.ip }, p)));
      });
      at(t0 + span, () => {
        emit({ type: 'host_done', host: h });
        emit({ type: 'log', msg: '-> ' + h.open_ports.length + ' open port(s) | OS: ' + h.os_guess });
      });
      clock += span + 40;
    });

    at(clock + 200, () => {
      const duration = (Date.now() - started) / 1000;
      const counts = { info: 0, low: 0, medium: 0, high: 0 };
      HOSTS.forEach((h) => h.findings.forEach((f) => { counts[f.severity] += 1; }));
      emit({
        type: 'done', hosts: HOSTS,
        meta: { target: '192.168.1.0/24', scan_time: new Date().toISOString().slice(0, 19).replace('T', ' '), duration: duration, ports_scanned: 38, discovered: total, cancelled: false, findings: counts }
      });
    });

    return function stop() { timers.forEach(clearTimeout); };
  }

  window.NemlaDemo = { run: run };
})();
