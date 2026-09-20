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
  const LINUX = 'Linux / Unix / macOS (TTL=64)', LINUX_SSH = 'Linux / Unix (SSH detected) (TTL=64)';
  const WIN = 'Windows (TTL=128)', WIN_RDP = 'Windows (RDP/SMB detected) (TTL=128)', NET = 'Network device (Cisco/Solaris) (TTL=255)';

  const P = (n, banner) => ({ port: n, service: SERVICES[n] || 'unknown', banner: banner || '' });
  const H = (last, os, ports, mac) => ({
    ip: '192.168.1.' + last, os_guess: os, ttl: /TTL=(\d+)/.test(os) ? +/TTL=(\d+)/.exec(os)[1] : null,
    mac: mac || null, discovery: 'ARP', open_ports: ports
  });

  const HOSTS = [
    H(1, NET, [P(53), P(80, 'HTTP/1.1 200 OK | Server: lighttpd/1.4.59'), P(443)], 'a4:2b:b0:1c:9e:10'),
    H(4, LINUX_SSH, [P(22, SSH), P(80, NGINX), P(443), P(3306), P(6379)], 'dc:a6:32:5e:11:07'),
    H(7, WIN_RDP, [P(135), P(139), P(445), P(3389)], '3c:52:82:aa:04:9d'),
    H(9, LINUX, [], 'f0:18:98:4d:c2:31'),
    H(12, LINUX_SSH, [P(22, SSH), P(2049), P(111), P(445), P(139), P(8080, APACHE)], 'b8:27:eb:73:5a:2c'),
    H(15, WIN, [P(135), P(445)], '00:1a:79:6c:31:be'),
    H(18, LINUX, [P(80, 'HTTP/1.1 200 OK | Server: Boa/0.94.14rc21'), P(23, 'login:')], '9c:b6:d0:0e:88:41'),
    H(21, LINUX_SSH, [P(22, SSH), P(25, '220 mail.lab.local ESMTP Postfix (Ubuntu)'), P(587), P(993), P(143)], '52:54:00:ab:31:c7'),
    H(23, LINUX, [], '8c:85:90:3a:70:11'),
    H(26, LINUX_SSH, [P(22, SSH), P(5432), P(9200, 'HTTP/1.1 200 OK')], '52:54:00:1e:9f:02'),
    H(30, WIN, [P(135), P(139), P(445), P(1433)], 'a0:36:9f:12:cb:84'),
    H(33, LINUX, [P(5900, 'RFB 003.008')], '68:54:5a:4e:0d:f3'),
    H(38, LINUX_SSH, [P(22, SSH), P(80, NGINX), P(443), P(8443)], '52:54:00:66:c2:d8'),
    H(41, LINUX, [], 'e4:5f:01:88:aa:65'),
    H(46, WIN_RDP, [P(135), P(139), P(445), P(3389)], '00:0c:29:f4:8b:1a'),
    H(52, LINUX_SSH, [P(22, SSH), P(27017), P(6379)], '52:54:00:d0:47:9c'),
    H(58, LINUX, [P(80, 'HTTP/1.1 401 Unauthorized | Server: Router-httpd')], '14:cc:20:9b:3e:75'),
    H(63, LINUX, [], '44:d9:e7:ab:12:0f'),
    H(70, LINUX_SSH, [P(21, '220 (vsFTPd 3.0.5)'), P(22, SSH), P(80, APACHE)], '52:54:00:73:e1:5b'),
    H(77, WIN, [P(445)], '2c:f0:5d:31:6a:c9'),
    H(84, LINUX, [P(22, 'SSH-2.0-dropbear_2022.83')], 'b0:be:76:15:d4:88'),
    H(91, LINUX_SSH, [P(22, SSH), P(80, NGINX), P(443), P(3306), P(9200, 'HTTP/1.1 200 OK')], '52:54:00:0b:c6:e4'),
    H(120, LINUX, [], '7c:2f:80:f8:29:d0'),
    H(200, LINUX_SSH, [P(22, SSH), P(8080, 'HTTP/1.1 200 OK | Server: Jetty(9.4.51)')], '52:54:00:c9:1d:6e')
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
      emit({
        type: 'done', hosts: HOSTS,
        meta: { target: '192.168.1.0/24', scan_time: new Date().toISOString().slice(0, 19).replace('T', ' '), duration: duration, ports_scanned: 38, discovered: total, cancelled: false }
      });
    });

    return function stop() { timers.forEach(clearTimeout); };
  }

  window.NemlaDemo = { run: run };
})();
