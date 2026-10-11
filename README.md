# ⚡ NetPulse — Intelligent Network Scanner & Security Analyzer

<p align="center">
  <strong>Next-Generation High-Speed Network Discovery, Deep Device Fingerprinting, and Security Posture Auditing</strong>
</p>

---

## 🌟 Overview & Philosophy

**NetPulse** is a modern, modular, asynchronous network scanner and defensive security analyzer built to replace legacy, single-threaded scanning scripts (such as `0xShun/Network-Scanner`). 

Where traditional scripts perform slow, sequential packet loops and require elevated root/WinPcap privileges, **NetPulse** provides:
- 🚀 **Blazing-Fast Async Sockets**: Scans 1,000+ ports per second natively with `asyncio` without requiring root or administrative privileges.
- 📡 **Stealth Raw Engine Integration**: Seamlessly switches to Scapy-powered Layer-2 ARP sweeps, stealth TCP SYN packets, and ICMP bursts when elevated permissions are present.
- 🏷️ **Hardware OUI & Hostname Intelligence**: Automatically resolves MAC addresses to manufacturers (Apple, Intel, Raspberry Pi, Espressif IoT, TP-Link) and discovers Windows NetBIOS computer names and reverse DNS.
- 🔍 **Active Banner Grabbing & Protocol Probing**: Interrogates open ports for HTTP/HTTPS server headers, HTML `<title>`, TLS/SSL certificates, SSH banners, Redis authentication states, and MySQL versions.
- 🛡️ **Automated Security Risk & Exposure Scoring**: Rates open services against an internal vulnerability catalog, scoring each host and generating an aggregate **Network Security Posture (Grade A–F)** with actionable remediation steps.
- 🌐 **Interactive Standalone HTML Network Topology**: Generates an interactive, draggable network topology graph (Vis.js) showing the Gateway, connected nodes, and open service clusters.
- 🚨 **Subnet Watcher Daemon**: Continuously monitors LAN subnets and alerts instantly when rogue devices join or MAC addresses change.

---

## 📊 Comparison: `0xShun/Network-Scanner` vs. `NetPulse`

| Capability | `0xShun/Network-Scanner` | `NetPulse` (This Project) |
| :--- | :--- | :--- |
| **Speed & Concurrency** | Synchronous sequential loop (~30 mins for 1,000 ports) | Async socket concurrency (1,000 ports in **< 2 seconds**) |
| **Privileges Required** | Strictly requires root/Npcap raw sockets | **Zero-privilege fallback** via native `asyncio` sockets |
| **Device Identification** | Raw MAC & IP only | **IEEE OUI Vendor DB** + NetBIOS names + Reverse DNS |
| **OS Heuristics** | None | Automatic OS inference (Windows, Linux, Apple, IoT) |
| **Service Inspection** | Port status only (`open`/`closed`) | Deep banner grabbing (HTTP, TLS certs, SSH, MySQL, Redis) |
| **Security Risk Scoring**| None | Port-level risk ranking (Critical/High/Med/Low) + Remediation tips |
| **Reporting & Visuals** | Plain stdout text | **Rich TUI Dashboard**, JSON, CSV, and **Interactive HTML Topology Map** |
| **Network Defense** | One-off scan only | **Continuous Subnet Watcher** & rogue device detection |

---

## 🚀 Quickstart & Installation

### Requirements
- **Python 3.9+** (Tested on Python 3.10 and 3.11)
- Windows, macOS, or Linux

### Installation

```bash
git clone https://github.com/your-username/NetPulse.git
cd NetPulse

# Install dependencies
pip install -r requirements.txt
```

*(Optional: For raw Layer-2 ARP sweeps and stealth SYN scanning on Windows, ensure [Npcap](https://npcap.com/) is installed and run as Administrator).*

---

## 💻 CLI Usage Guide

NetPulse is invoked using `python main.py` or via the `netpulse` CLI command.

### 1. Basic Port Scan
Scan a single IP or hostname using the default `top-100` ports:
```bash
python main.py scan 192.168.1.1
```

### 2. Using Port Presets & Ranges
```bash
# Scan top 20 ports
python main.py scan 127.0.0.1 -p top-20

# Scan web servers
python main.py scan 192.168.1.50 -p web

# Scan databases
python main.py scan 10.0.0.15 -p databases

# Scan custom ranges
python main.py scan 192.168.1.10 -p 1-1000
python main.py scan 192.168.1.10 -p 80,443,8080,3306
```

### 3. Generate Interactive HTML Network Topology Report
Creates a standalone, dependency-free HTML report featuring a dynamic force-directed network map and searchable vulnerability audit cards:
```bash
python main.py scan 192.168.1.1 --html
```
*(Open the generated `netpulse_report_192.168.1.1.html` in any browser!)*

### 4. Subnet Sweep & Discovery
Scan an entire `/24` subnet:
```bash
python main.py scan 192.168.1.0/24 -p top-20 --html
```

### 5. Structured Data Exports (JSON / CSV)
```bash
# Export to JSON
python main.py scan 192.168.1.0/24 -o audit_report.json

# Export to CSV spreadsheet
python main.py scan 192.168.1.0/24 -o network_inventory.csv
```

### 6. Hardware MAC Vendor Lookup (OUI)
Instantly resolve any MAC address to its hardware manufacturer:
```bash
python main.py oui b8:27:eb:11:22:33
# Output: Manufacturer / Vendor: Raspberry Pi Foundation

python main.py oui 24:6f:28:99:88:77
# Output: Manufacturer / Vendor: Espressif Inc.
```

### 7. Continuous Subnet Watcher (Rogue Device Detector)
Monitor your local subnet continuously and alert immediately when unknown devices join:
```bash
python main.py watch 192.168.1.0/24 -i 15
```

### 8. List Available Port Profiles
```bash
python main.py list-profiles
```

---

## 🏗️ Architecture & Modules

```
NetPulse/
├── netpulse/
│   ├── cli.py                     # Rich CLI interface & command handlers
│   ├── engine/
│   │   ├── async_scanner.py       # High-speed asyncio non-blocking socket engine
│   │   ├── raw_scanner.py         # Scapy ARP/SYN/ICMP engine (when elevated)
│   │   └── hybrid.py              # Engine coordinator & data models
│   ├── fingerprint/
│   │   ├── oui.py                 # IEEE MAC vendor resolution database
│   │   ├── banners.py             # HTTP, TLS, SSH, MySQL, Redis protocol inspectors
│   │   └── discovery.py           # NetBIOS, mDNS, and reverse DNS identity
│   ├── analyzer/
│   │   ├── risk_rules.py          # Vulnerability catalog & severity weights
│   │   └── posture.py             # Security score & remediation engine
│   ├── reporting/
│   │   ├── console.py             # Rich TUI tables & live progress bars
│   │   ├── json_export.py         # JSON and CSV export handlers
│   │   └── topology_html.py       # Vis.js interactive network topology generator
│   └── watcher/
│       └── monitor.py             # Background subnet watcher daemon
├── tests/
│   ├── test_engine.py             # Port parsing & async socket tests
│   ├── test_fingerprint.py        # OUI vendor & MAC normalization tests
│   └── test_analyzer.py           # Vulnerability rules & posture scoring tests
├── main.py                        # Entry-point script
├── pyproject.toml                 # Package configuration
└── requirements.txt               # Dependencies
```

---

## 🧪 Running Unit Tests

NetPulse includes unit test coverage for engine concurrency, OUI vendor parsing, banner overrides, and security grading:

```bash
pytest -v
```

```text
============================= test session starts =============================
tests/test_analyzer.py::test_evaluate_port_risk PASSED                   [  7%]
tests/test_analyzer.py::test_banner_override_risk PASSED                 [ 14%]
tests/test_analyzer.py::test_host_security_posture_clean PASSED          [ 21%]
tests/test_analyzer.py::test_host_security_posture_critical PASSED       [ 28%]
tests/test_analyzer.py::test_infer_os PASSED                             [ 35%]
tests/test_engine.py::test_parse_single_port PASSED                      [ 42%]
tests/test_engine.py::test_parse_port_list PASSED                        [ 50%]
tests/test_engine.py::test_parse_port_range PASSED                       [ 57%]
tests/test_engine.py::test_parse_named_profiles PASSED                   [ 64%]
tests/test_engine.py::test_parse_invalid_ports PASSED                    [ 71%]
tests/test_engine.py::test_async_scanner_mock_closed PASSED              [ 78%]
tests/test_fingerprint.py::test_normalize_mac PASSED                     [ 85%]
tests/test_fingerprint.py::test_oui_vendor_lookup PASSED                 [ 92%]
tests/test_fingerprint.py::test_randomized_mac_detection PASSED          [100%]
============================= 14 passed in 0.31s ==============================
```

---

## ⚖️ License & Ethical Use

NetPulse is released under the **MIT License**. It is created strictly for authorized network administration, educational research, and defensive security auditing. Always obtain explicit permission before scanning networks you do not own.
#   N e t P u l s e  
 