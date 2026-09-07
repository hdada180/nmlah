#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
أداة استطلاع شبكة شاملة — Nemla (نملة)
اكتشاف أجهزة + فحص منافذ + تخمين نظام تشغيل + تقرير HTML

الاستخدام:
sudo python3 nemla.py -t 192.168.1.0/24
sudo python3 nemla.py -t 192.168.1.1-50 -p 1-1000
sudo python3 nemla.py -t 192.168.1.10 --top-ports

ملاحظة: استخدمها فقط على شبكات لديك صلاحية صريحة لفحصها.
"""

import argparse
import ipaddress
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue

try:
    from scapy.all import ARP, Ether, srp, sr1, IP, ICMP, conf as scapy_conf
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

VERSION = "1.0"

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1080, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 5985,
    6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017, 3128, 6000, 8081,
]

COMMON_SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    3128: "Squid",
    6000: "X11",
    8081: "HTTP-Alt",
}

PRINT_LOCK = threading.Lock()


def log(msg):
    with PRINT_LOCK:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {msg}")


def banner():
    art = "\n".join([
        " __ _ ",
        " / \\.--.-./ \\ نملة | Nemla Network Recon",
        " \\ - - / v{ver}".format(ver=VERSION),
        " .---'-- --'---.",
        "اكتشاف أجهزة + فحص منافذ",
        "تخمين نظام التشغيل + تقرير HTML",
        " \\ - - /",
        " '---.__ __.---'",
        " `-. . .-`",
    ])

    print(art)


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def arp_scan(subnet):
    """ARP-based discovery for a local subnet using scapy."""

    log(f"بدء اكتشاف الأجهزة على {subnet} (ARP)...")

    hosts = []

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet)),
            timeout=3,
            retry=1,
            verbose=0,
        )

        for _, rcv in ans:
            hosts.append({
                "ip": rcv.psrc,
                "mac": rcv.hwsrc
            })

    except PermissionError:
        log("صلاحيات غير كافية لـ ARP scan. جرب sudo.")
        return None

    except Exception as e:
        log(f"فشل ARP scan ({e})، سيتم الرجوع إلى TCP/ICMP.")
        return None

    return hosts


def tcp_ping(ip, ports=(80, 443, 22, 445, 3389), timeout=0.6):
    """Fallback host-up check using TCP."""

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)

                if s.connect_ex((str(ip), port)) == 0:
                    return True

        except Exception:
            continue

    return False


def icmp_ping(ip):
    """OS ping fallback."""

    try:
        param = "-n" if sys.platform.lower().startswith("win") else "-c"

        result = subprocess.run(
            ["ping", param, "1", "-W", "1", str(ip)]
            if not sys.platform.lower().startswith("win")
            else ["ping", param, "1", "-w", "1000", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )

        return result.returncode == 0

    except Exception:
        return False


def discover_hosts(network, max_workers=100):
    """Try ARP first, then ICMP + TCP."""

    discovered = {}

    if HAVE_SCAPY:
        arp_results = arp_scan(network)

        if arp_results is not None:
            for h in arp_results:
                discovered[h["ip"]] = {
                    "mac": h["mac"],
                    "method": "ARP"
                }

            log(f"تم اكتشاف {len(discovered)} جهاز")
            return discovered

    log(f"بدء اكتشاف الأجهزة على {network} باستخدام ICMP + TCP...")

    ip_list = (
        list(network.hosts())
        if network.num_addresses > 1
        else [network.network_address]
    )

    def probe(ip):
        if icmp_ping(ip) or tcp_ping(ip):
            return str(ip)

        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(probe, ip): ip
            for ip in ip_list
        }

        for fut in as_completed(futures):
            res = fut.result()

            if res:
                discovered[res] = {
                    "mac": None,
                    "method": "ICMP/TCP"
                }

    log(f"تم اكتشاف {len(discovered)} جهاز")

    return discovered


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

def parse_ports(port_spec):
    ports = set()

    for part in port_spec.split(","):
        part = part.strip()

        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))

        elif part:
            ports.add(int(part))

    return sorted(ports)


def grab_banner(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass

            data = s.recv(256)

            return (
                data.decode(errors="ignore")
                .strip()
                .split("\n")[0][:80]
            )

    except Exception:
        return ""


def scan_port(ip, port, timeout=0.7, grab=True):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)

            if s.connect_ex((ip, port)) == 0:
                service = COMMON_SERVICE_NAMES.get(
                    port,
                    "unknown"
                )

                b = grab_banner(ip, port) if grab else ""

                return port, service, b

    except Exception:
        pass

    return None


def scan_host_ports(ip, ports, max_workers=200):
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [
            ex.submit(scan_port, ip, p)
            for p in ports
        ]

        for fut in as_completed(futures):
            res = fut.result()

            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x[0])

    return open_ports


# ---------------------------------------------------------------------------
# OS fingerprinting
# ---------------------------------------------------------------------------

def guess_os_by_ttl(ip):
    ttl = None

    if HAVE_SCAPY:
        try:
            pkt = sr1(
                IP(dst=ip) / ICMP(),
                timeout=1,
                verbose=0
            )

            if pkt:
                ttl = pkt.ttl

        except Exception:
            ttl = None

    if ttl is None:
        try:
            param = "-n" if sys.platform.lower().startswith("win") else "-c"

            out = subprocess.run(
                ["ping", param, "1", str(ip)],
                capture_output=True,
                text=True,
                timeout=2
            ).stdout

            for line in out.splitlines():
                if "ttl=" in line.lower():
                    ttl = int(
                        line.lower()
                        .split("ttl=")[1]
                        .split()[0]
                    )
                    break

        except Exception:
            ttl = None

    if ttl is None:
        return "غير معروف", None

    if ttl <= 64:
        return "Linux / Unix / macOS", ttl

    elif ttl <= 128:
        return "Windows", ttl

    else:
        return "Network device (Cisco/Solaris)", ttl


def refine_os_guess(base_guess, open_ports):
    port_nums = {p[0] for p in open_ports}

    if 3389 in port_nums or (445 in port_nums and 135 in port_nums):
        return "Windows (RDP/SMB مكتشفة)"

    if 22 in port_nums and base_guess.startswith("Linux"):
        return "Linux / Unix (SSH مكتشف)"

    return base_guess


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ar" dir="rtl">

<head>
<meta charset="UTF-8">

<title>تقرير نملة - {target}</title>

<style>

:root {{
    --bg: #0d0d0d;
    --panel: #171512;
    --ant-orange: #ff8c00;
    --ant-orange-dim: #b35f00;
    --text: #eee8dc;
    --text-dim: #9a9184;
    --border: #2a251f;
    --up: #6fcf6f;
    --down: #666;
}}

* {{
    box-sizing: border-box;
}}

body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
    margin: 0;
    padding: 0 0 60px 0;
}}

header {{
    background: linear-gradient(135deg, #1a1611, #0d0d0d);
    border-bottom: 2px solid var(--ant-orange);
    padding: 28px 32px;
    display: flex;
    align-items: center;
    gap: 18px;
}}

header .icon {{
    font-size: 42px;
}}

header h1 {{
    margin: 0;
    color: var(--ant-orange);
    font-size: 26px;
}}

header p {{
    margin: 4px 0 0;
    color: var(--text-dim);
    font-size: 13px;
}}

.summary {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    padding: 20px 32px 0;
}}

.stat {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 20px;
    min-width: 140px;
}}

.stat .num {{
    font-size: 26px;
    font-weight: 700;
    color: var(--ant-orange);
}}

.stat .label {{
    font-size: 12px;
    color: var(--text-dim);
    margin-top: 2px;
}}

.container {{
    padding: 24px 32px;
}}

.host-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 18px;
    overflow: hidden;
}}

.host-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    background: #1c1812;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    gap: 8px;
}}

.host-ip {{
    font-size: 17px;
    font-weight: 700;
    color: var(--text);
}}

.badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    margin-inline-start: 8px;
}}

.badge.up {{
    background: rgba(111,207,111,0.15);
    color: var(--up);
    border: 1px solid var(--up);
}}

.badge.os {{
    background: rgba(255,140,0,0.12);
    color: var(--ant-orange);
    border: 1px solid var(--ant-orange-dim);
}}

.host-meta {{
    font-size: 12px;
    color: var(--text-dim);
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th,
td {{
    text-align: right;
    padding: 10px 20px;
    font-size: 13px;
}}

th {{
    color: var(--text-dim);
    font-weight: 600;
    border-bottom: 1px solid var(--border);
}}

td {{
    border-bottom: 1px solid var(--border);
}}

tr:last-child td {{
    border-bottom: none;
}}

.port {{
    color: var(--ant-orange);
    font-weight: 700;
    font-family: monospace;
}}

.service {{
    color: var(--text);
}}

.banner {{
    color: var(--text-dim);
    font-family: monospace;
    font-size: 11px;
}}

.no-ports {{
    padding: 16px 20px;
    color: var(--text-dim);
    font-size: 13px;
}}

footer {{
    text-align: center;
    color: var(--text-dim);
    font-size: 12px;
    padding: 30px;
}}

</style>

</head>

<body>

<header>

<div class="icon">🐜</div>

<div>

<h1>تقرير نملة — Nemla Recon Report</h1>

<p>
الهدف: {target}
&nbsp;|&nbsp;
تاريخ الفحص: {scan_time}
&nbsp;|&nbsp;
المدة: {duration}s
</p>

</div>

</header>

<div class="summary">

<div class="stat">
<div class="num">{host_count}</div>
<div class="label">أجهزة مكتشفة</div>
</div>

<div class="stat">
<div class="num">{total_open_ports}</div>
<div class="label">منافذ مفتوحة</div>
</div>

<div class="stat">
<div class="num">{ports_scanned}</div>
<div class="label">منفذ تم فحصه لكل جهاز</div>
</div>

</div>

<div class="container">

{host_cards}

</div>

<footer>
🐜 تم توليده بواسطة نملة (Nemla) v{version}
— استخدام مسؤول فقط على شبكات مصرح بفحصها
</footer>

</body>

</html>
"""


HOST_CARD_TEMPLATE = """
<div class="host-card">

<div class="host-header">

<div>

<span class="host-ip">{ip}</span>

<span class="badge up">Active</span>

<span class="badge os">{os_guess}</span>

</div>

<div class="host-meta">
{mac_line}
</div>

</div>

{ports_table}

</div>
"""


def render_host_card(ip, mac, os_guess, open_ports):

    mac_line = f"MAC: {mac}" if mac else ""

    if open_ports:

        rows = "\n".join(
            f'<tr>'
            f'<td class="port">{p}</td>'
            f'<td class="service">{svc}</td>'
            f'<td class="banner">{(b or "-")}</td>'
            f'</tr>'
            for p, svc, b in open_ports
        )

        ports_table = f"""
<table>

<tr>
<th>المنفذ</th>
<th>الخدمة</th>
<th>Banner</th>
</tr>

{rows}

</table>
"""

    else:

        ports_table = """
<div class="no-ports">
لا توجد منافذ مفتوحة ضمن النطاق المفحوص
</div>
"""

    return HOST_CARD_TEMPLATE.format(
        ip=ip,
        mac_line=mac_line,
        os_guess=os_guess,
        ports_table=ports_table
    )


def generate_report(
    target,
    results,
    ports_scanned_count,
    duration,
    out_path
):

    host_cards = "\n".join(
        render_host_card(
            ip,
            data["mac"],
            data["os_guess"],
            data["open_ports"]
        )
        for ip, data in results.items()
    )

    total_open = sum(
        len(d["open_ports"])
        for d in results.values()
    )

    html = HTML_TEMPLATE.format(
        target=target,
        scan_time=datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        duration=f"{duration:.1f}",
        host_count=len(results),
        total_open_ports=total_open,
        ports_scanned=ports_scanned_count,
        host_cards=(
            host_cards
            or '<p style="color:#9a9184">لا توجد أجهزة لعرضها</p>'
        ),
        version=VERSION,
    )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    return out_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="نملة — أداة استطلاع شبكة شاملة"
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="IP / CIDR / نطاق"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        help="نطاق المنافذ مثال: 1-1000 أو 22,80,443"
    )

    parser.add_argument(
        "--top-ports",
        action="store_true",
        help="فحص أهم المنافذ الشائعة فقط"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="nemla_report.html",
        help="مسار ملف تقرير HTML"
    )

    parser.add_argument(
        "--no-os",
        action="store_true",
        help="تخطي تخمين نظام التشغيل"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=150,
        help="عدد الخيوط للفحص المتوازي"
    )

    args = parser.parse_args()

    banner()

    start = time.time()

    target_raw = args.target

    try:

        if "-" in target_raw and "/" not in target_raw:

            start_ip = target_raw.split("-")[0]
            end = target_raw.split("-")[-1]

            start_last_octet = int(
                start_ip.split(".")[-1]
            )

            end_last_octet = int(end)

            prefix = ".".join(
                start_ip.split(".")[:-1]
            )

            ip_list = [
                f"{prefix}.{i}"
                for i in range(
                    start_last_octet,
                    end_last_octet + 1
                )
            ]

            network = ipaddress.ip_network(
                f"{prefix}.0/24",
                strict=False
            )

            hosts_map = discover_hosts_from_list(
                ip_list
            )

        else:

            network = ipaddress.ip_network(
                target_raw,
                strict=False
            )

            hosts_map = discover_hosts(
                network,
                max_workers=args.threads
            )

    except ValueError as e:

        log(f"صيغة هدف غير صالحة: {e}")
        sys.exit(1)

    if not hosts_map:

        log(
            "لم يتم اكتشاف أي جهاز. "
            "تأكد من الاتصال بالشبكة أو جرب sudo."
        )

        sys.exit(0)

    ports = (
        parse_ports(args.ports)
        if args.ports
        else TOP_PORTS
    )

    log(
        f"نطاق المنافذ: {len(ports)} منفذ لكل جهاز"
    )

    results = {}

    for ip, meta in hosts_map.items():

        log(f"فحص {ip} ...")

        open_ports = scan_host_ports(
            ip,
            ports,
            max_workers=args.threads
        )

        if args.no_os:

            os_guess = "تم التخطي"
            ttl = None

        else:

            base_guess, ttl = guess_os_by_ttl(ip)

            os_guess = refine_os_guess(
                base_guess,
                open_ports
            )

        if not args.no_os and ttl:
            os_guess += f" (TTL={ttl})"

        results[ip] = {
            "mac": meta.get("mac"),
            "os_guess": os_guess,
            "open_ports": open_ports,
        }

        log(
            f"↳ {len(open_ports)} منفذ مفتوح | "
            f"OS: {os_guess}"
        )

    duration = time.time() - start

    out_path = generate_report(
        target_raw,
        results,
        len(ports),
        duration,
        args.output
    )

    log(
        f"اكتمل الفحص خلال {duration:.1f} ثانية"
    )

    log(
        f"التقرير: {out_path}"
    )


def discover_hosts_from_list(
    ip_list,
    max_workers=100
):

    discovered = {}

    def probe(ip):

        if icmp_ping(ip) or tcp_ping(ip):
            return ip

        return None

    log(
        f"بدء اكتشاف الأجهزة على "
        f"{len(ip_list)} عنوان محدد..."
    )

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as ex:

        futures = {
            ex.submit(probe, ip): ip
            for ip in ip_list
        }

        for fut in as_completed(futures):

            res = fut.result()

            if res:

                discovered[res] = {
                    "mac": None,
                    "method": "ICMP/TCP"
                }

    log(
        f"تم اكتشاف {len(discovered)} جهاز"
    )

    return discovered


if __name__ == "__main__":

    if (
        not sys.platform.lower().startswith("win")
        and __import__("os").geteuid() != 0
    ):

        log(
            "تنبيه: بعض الميزات مثل ARP scan وICMP "
            "تحتاج صلاحيات root. جرب: "
            "sudo python3 nemla.py ..."
        )

    main()