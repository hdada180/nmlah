# 🐜 Nemla — Network Reconnaissance Tool

<p align="center">

**DISCOVER · SCAN · FINGERPRINT · REPORT**

A lightweight and efficient **network reconnaissance tool written in Python**, designed for authorized security testing, network administration, cybersecurity labs, and educational research.

Nemla discovers active hosts, scans TCP ports, identifies common services, performs basic OS fingerprinting, grabs service banners, and generates a clean HTML report.

</p>

<p align="center">

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Unix-lightgrey?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0-orange?style=for-the-badge)
![Security](https://img.shields.io/badge/Purpose-Network%20Recon-red?style=for-the-badge)

</p>

---

## 🧭 Overview

**Nemla** — Arabic: **نملة**, meaning *ant* — is a network reconnaissance utility built around a simple idea:

> **Discover → Scan → Identify → Analyze → Report**

It provides a practical workflow for obtaining an initial view of a network and the services exposed by its active hosts.

```text
                         ┌──────────────────────┐
                         │      NEMLA 🐜         │
                         │ Network Recon Tool    │
                         └───────────┬──────────┘
                                     │
                                     ▼
                         ┌──────────────────────┐
                         │   Host Discovery     │
                         │ ARP / ICMP / TCP      │
                         └───────────┬──────────┘
                                     │
                                     ▼
                         ┌──────────────────────┐
                         │    Port Scanning     │
                         │   Concurrent TCP     │
                         └───────────┬──────────┘
                                     │
                                     ▼
                         ┌──────────────────────┐
                         │ Service Identification│
                         │  Banner Collection   │
                         └───────────┬──────────┘
                                     │
                                     ▼
                         ┌──────────────────────┐
                         │  OS Fingerprinting   │
                         │    TTL + Services    │
                         └───────────┬──────────┘
                                     │
                                     ▼
                         ┌──────────────────────┐
                         │     HTML Report      │
                         │  Results & Summary   │
                         └──────────────────────┘
```

---

# ✨ Features

## 🛰️ Host Discovery

Nemla supports multiple discovery techniques to identify active hosts:

* **ARP discovery** using Scapy.
* **ICMP ping** discovery.
* **TCP probing** against common ports.
* CIDR network targets.
* Explicit IP ranges.

Supported target examples:

```text
192.168.1.0/24
192.168.1.1
192.168.1.1-50
```

---

## 🔎 TCP Port Scanning

Nemla performs concurrent TCP connection scanning using Python's `ThreadPoolExecutor`.

You can scan:

* A single port.
* A list of ports.
* A port range.
* A predefined list of common ports.

Examples:

```bash
-p 22
```

```bash
-p 22,80,443
```

```bash
-p 1-1000
```

```bash
--top-ports
```

---

## 🧩 Service Identification

Nemla maps discovered ports to commonly associated services.

|  Port | Service         |
| ----: | --------------- |
|    21 | FTP             |
|    22 | SSH             |
|    23 | Telnet          |
|    25 | SMTP            |
|    53 | DNS             |
|    80 | HTTP            |
|   110 | POP3            |
|   111 | RPCBind         |
|   135 | MS-RPC          |
|   139 | NetBIOS         |
|   143 | IMAP            |
|   443 | HTTPS           |
|   445 | SMB             |
|   465 | SMTPS           |
|   587 | SMTP Submission |
|   993 | IMAPS           |
|   995 | POP3S           |
|  1433 | MSSQL           |
|  1521 | Oracle          |
|  1723 | PPTP            |
|  2049 | NFS             |
|  3306 | MySQL           |
|  3389 | RDP             |
|  5432 | PostgreSQL      |
|  5900 | VNC             |
|  5985 | WinRM           |
|  6379 | Redis           |
|  8080 | HTTP Alternate  |
|  8081 | HTTP Alternate  |
|  9200 | Elasticsearch   |
| 11211 | Memcached       |
| 27017 | MongoDB         |
|  3128 | Squid           |
|  6000 | X11             |

---

## 🏷️ Banner Grabbing

When possible, Nemla attempts to collect a service banner from open TCP ports.

Example:

```text
Port: 22
Service: SSH
Banner: SSH-2.0-OpenSSH_8.9
```

Banner information can provide useful context during reconnaissance and service identification.

---

## 🖥️ OS Fingerprinting

Nemla performs basic operating-system fingerprinting using:

* TCP/IP TTL values.
* Detected services.
* Common Windows indicators such as SMB and RDP.
* SSH indicators for Linux/Unix-like systems.

Example:

```text
OS Guess: Linux / Unix
TTL: 64
Indicator: SSH
```

or:

```text
OS Guess: Windows
TTL: 128
Indicators: SMB / RDP
```

> **Note:** OS fingerprinting is heuristic and should be treated as an estimate rather than definitive identification.

---

# 📊 HTML Reporting

Nemla automatically generates a structured **HTML reconnaissance report**.

The report includes:

* Scan target.
* Scan timestamp.
* Scan duration.
* Number of discovered devices.
* Number of open ports.
* Number of scanned ports.
* Host status.
* IP addresses.
* MAC addresses when available.
* OS fingerprint results.
* Open ports.
* Service names.
* Service banners.

The report uses a dark interface with an orange Nemla-inspired visual identity.

Example structure:

```text
Nemla Report
│
├── Scan Summary
│   ├── Devices Discovered
│   ├── Open Ports
│   ├── Ports Scanned
│   └── Scan Duration
│
├── Host Information
│   ├── IP Address
│   ├── Status
│   ├── Operating System
│   └── MAC Address
│
└── Open Ports
    ├── Port
    ├── Service
    └── Banner
```

---

# 🚀 Installation

## Requirements

Nemla requires:

* Python 3.x
* Scapy
* A Unix/Linux environment is recommended for full discovery functionality.
* Appropriate privileges may be required for certain network discovery operations.

### Install Scapy

```bash
pip3 install scapy
```

or:

```bash
pip install scapy
```

### Clone the repository

```bash
git clone https://github.com/hdada180/nmlah.git
cd nmlah
```

---

# ⚡ Quick Start

## Scan a CIDR network

```bash
sudo python3 nemla.py -t 192.168.1.0/24
```

---

## Scan an IP range

```bash
sudo python3 nemla.py -t 192.168.1.1-50
```

---

## Scan a specific host

```bash
sudo python3 nemla.py -t 192.168.1.10
```

---

## Scan a port range

```bash
sudo python3 nemla.py \
  -t 192.168.1.10 \
  -p 1-1000
```

---

## Scan specific ports

```bash
sudo python3 nemla.py \
  -t 192.168.1.10 \
  -p 22,80,443,445,3389
```

---

## Scan common ports

```bash
sudo python3 nemla.py \
  -t 192.168.1.10 \
  --top-ports
```

---

## Generate a custom report

```bash
sudo python3 nemla.py \
  -t 192.168.1.0/24 \
  --top-ports \
  -o nemla_report.html
```

---

## Disable OS fingerprinting

```bash
sudo python3 nemla.py \
  -t 192.168.1.0/24 \
  --no-os
```

---

## Increase or decrease scan threads

```bash
sudo python3 nemla.py \
  -t 192.168.1.0/24 \
  --threads 100
```

---

# 🛠️ Command-Line Options

| Option           | Description                                  |
| ---------------- | -------------------------------------------- |
| `-t`, `--target` | Target IP, CIDR network, or IP range         |
| `-p`, `--ports`  | Ports, comma-separated ports, or port ranges |
| `--top-ports`    | Scan the predefined common-port list         |
| `-o`, `--output` | Output HTML report path                      |
| `--no-os`        | Disable OS fingerprinting                    |
| `--threads`      | Number of concurrent worker threads          |

---

# 🧠 Architecture

Nemla follows a simple reconnaissance pipeline.

### 1. Discovery

The tool first attempts to identify active hosts.

```text
Target Network
      │
      ├── ARP Discovery
      │
      ├── ICMP Discovery
      │
      └── TCP Probing
```

---

### 2. Port Scanning

Discovered hosts are then scanned for the selected TCP ports.

```text
Host
 │
 ├── 22/tcp
 ├── 80/tcp
 ├── 443/tcp
 ├── 445/tcp
 ├── 3389/tcp
 └── ...
```

---

### 3. Fingerprinting

Nemla analyzes the scan results to estimate the operating system and identify services.

```text
TTL
 │
 ├── OS Guess
 │
 └── Service Indicators
```

---

### 4. Reporting

Finally, all collected information is transformed into an HTML report.

```text
Scan Results
      │
      ▼
nemla_report.html
```

---

# ⚙️ Performance

Nemla uses concurrent workers to improve scanning performance.

The number of threads can be configured using:

```bash
--threads
```

Example:

```bash
sudo python3 nemla.py \
  -t 192.168.1.0/24 \
  --top-ports \
  --threads 150
```

Actual performance depends on:

* Network size.
* Number of ports.
* Network latency.
* Firewall behavior.
* Host responsiveness.
* System resources.
* Number of concurrent threads.

---

# 📁 Project Structure

```text
nmlah/
│
├── nemla.py
├── README.md
├── nemla_report_sample.html
└── LICENSE
```

The main components are:

| File                       | Purpose                  |
| -------------------------- | ------------------------ |
| `nemla.py`                 | Main reconnaissance tool |
| `README.md`                | Project documentation    |
| `nemla_report_sample.html` | Example HTML report      |
| `LICENSE`                  | Project license          |

---

# 🧪 Example Output

A discovered Linux/Unix host may appear as:

```text
Host: 192.168.1.1
Status: Active
OS: Linux / Unix
TTL: 64

Open Ports:

22/tcp    SSH
80/tcp    HTTP
```

A Windows host may appear as:

```text
Host: 192.168.1.20
Status: Active
OS: Windows
TTL: 128

Open Ports:

445/tcp   SMB
3389/tcp  RDP
```

---

# 🎯 Use Cases

Nemla is intended for **authorized** security and network-management scenarios, including:

* 🔬 Cybersecurity education.
* 🧪 Security laboratories.
* 🛡️ Authorized network assessments.
* 🖥️ Network administration.
* 🔎 Initial network reconnaissance.
* 📚 Learning TCP port scanning.
* 🧠 Learning basic OS fingerprinting.
* 📑 Generating reconnaissance reports.
* 🏠 Testing personal/lab networks.

---

# 🔐 Responsible Use

Nemla is a reconnaissance tool.

**Only scan systems and networks that you own or have explicit permission to test.**

Unauthorized scanning may violate:

* Organizational policies.
* Network-provider terms.
* Local laws.
* Applicable cybersecurity regulations.

The author is not responsible for misuse of this software.

> **Use Nemla responsibly. Scan with permission. 🐜**

---

# 🛡️ Security Philosophy

Nemla focuses on **visibility and information gathering**, not exploitation.

Its purpose is to answer questions such as:

```text
What devices are active?
        ↓
What ports are exposed?
        ↓
What services appear to be running?
        ↓
What OS might the host be using?
        ↓
How can the results be documented?
```

This makes Nemla useful as an introductory reconnaissance layer before deeper, authorized security assessment.

---

# 🗺️ Roadmap

Potential future improvements may include:

* [ ] More advanced OS fingerprinting.
* [ ] Expanded service detection.
* [ ] Improved banner parsing.
* [ ] IPv6 support.
* [ ] Better MAC/vendor identification.
* [ ] JSON output.
* [ ] CSV output.
* [ ] Richer HTML dashboards.
* [ ] Scan profiles.
* [ ] Configuration files.
* [ ] Improved error handling.
* [ ] Unit and integration tests.
* [ ] More discovery methods.
* [ ] Plugin-based service detection.

---

# 🤝 Contributing

Contributions are welcome.

A simple workflow:

```bash
git clone https://github.com/hdada180/nmlah.git
cd nmlah
```

Create a feature branch:

```bash
git checkout -b feature/my-improvement
```

Make your changes, test them in an authorized environment, and submit a pull request.

When contributing, please aim for:

* Clean Python code.
* Clear documentation.
* Minimal unnecessary dependencies.
* Safe and responsible functionality.
* Reproducible testing.

---

# 🐛 Bug Reports & Feature Requests

Found a bug or have an idea?

Please open an issue in the GitHub repository and include:

```text
1. Operating system
2. Python version
3. Nemla version
4. Command used
5. Expected behavior
6. Actual behavior
7. Relevant error output
```

Avoid publishing sensitive network information, credentials, private IP inventories, or other confidential data in public issues.

---

# 📜 License

This project is distributed under the license included in the repository.

See:

```text
LICENSE
```

for the complete terms and conditions.

---

# 🐜 The Name

Why **Nemla**?

Because an ant may be tiny, but it can explore an entire environment.

```text
       🐜
      /|\
     / | \
    /  |  \
       |
   DISCOVER
      ↓
     SCAN
      ↓
   IDENTIFY
      ↓
    REPORT
```

**Small tool.
Big visibility.**

---

# ⭐ Support the Project

If Nemla is useful to you:

* ⭐ Star the repository.
* 🐛 Report bugs.
* 💡 Suggest improvements.
* 🔧 Contribute code.
* 📖 Improve the documentation.
* 🧪 Test it in authorized environments.

Every contribution helps Nemla grow.

---

<p align="center">

# 🐜 Nemla

### **Network Reconnaissance, Simplified.**

**Discover. Scan. Fingerprint. Report.**

</p>

<p align="center">

Made with ❤️ and Python 🐍

</p>

---

> ⚠️ **LEGAL & ETHICAL NOTICE**
>
> Nemla is intended exclusively for authorized security testing, network administration, cybersecurity education, and laboratory environments. Always obtain appropriate authorization before scanning a network or system.

