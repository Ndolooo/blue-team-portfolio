# 🍯 T-Pot Honeypot — Threat Intelligence Analysis

**MSc Applied Cybersecurity Research Project | TU Dublin**

---

## 📌 Project Overview

This project involved deploying a **T-Pot multi-honeypot environment** on a live cloud server to observe, capture, and analyse real-world cyberattacks. The environment was exposed to the internet for approximately **two months**, during which it captured over **2,000,000 attack events**.

The goal was to:
- Observe real attacker behaviour and tactics in a controlled environment
- Extract threat intelligence from captured logs
- Reconstruct a full intrusion chain
- Identify malware families delivered during attacks
- Map attacker behaviour to the MITRE ATT&CK framework

---

## 🖥️ Environment Setup

| Component | Detail |
|---|---|
| Cloud Provider | DigitalOcean |
| Operating System | Ubuntu 22.04 LTS x64 |
| CPU | 4 Cores |
| RAM | 8 GB |
| Storage | 160 GB SSD |
| Honeypot Framework | T-Pot (Deutsche Telekom) |
| Honeypot Sensors | Cowrie, Dionaea, Honeytrap, Sentrypeer, Suricata |
| Logging & Visualisation | ELK Stack (Elasticsearch, Logstash, Kibana) |
| Observation Period | ~2 months (continuous) |

---

## 📊 Key Statistics

| Metric | Value |
|---|---|
| Total Attacks Captured | **2,000,000+** |
| Top Honeypot by Attacks | Honeytrap (~600,000 attacks) |
| Top Targeted Ports | 5060 (VoIP/SIP), 22 (SSH) |
| Top Source Countries | USA, Romania, Netherlands, Ukraine, France |
| Known Malicious IPs | 1,068,897 instances |
| Mass Scanners | 31,083 instances |
| Malware Families Identified | Mirai, Tsunami, Backdoor:Linux |

---

## 🔬 What Was Analysed

### Top 3 Honeypots by Attack Volume
1. **Honeytrap** (~600,000 attacks) — Dynamic interaction across ports including SSH and HTTP
2. **Cowrie** — Medium-interaction SSH/Telnet honeypot; captured full attacker command sessions
3. **Sentrypeer** — P2P honeypot detecting SIP/VoIP brute-force attacks

### Attack Origin
Attacks originated primarily from **known malicious IPs** (1,068,897 instances) rather than anonymisation tools, confirming the value of threat intelligence feed blocking. Top ASNs abused included:
- AS47890 — Unmanaged Ltd (310,165 attacks)
- AS14061 — DigitalOcean
- AS396982 — Google Cloud
- AS8075 — Microsoft Azure

### Suricata CVEs Detected
- **CVE-2020-11900** — Treck TCP/IP stack IPv4 tunnelling double-free vulnerability
- **CVE-2020-11910** — CVSS 9.8 — Out-of-bounds Read in Treck TCP/IP stack

---

## 🔗 Detailed Reports

| Report | Description |
|---|---|
| [Attack Chain](./attack-chain.md) | Full reconstructed Cowrie intrusion sequence |
| [IOC Report](./ioc-report.md) | Attacker IPs, malicious URLs, commands, file hashes |
| [Findings Summary](./findings-summary.md) | Statistics, malware families, MITRE ATT&CK mapping |

---

## 🛠️ Tools Used

- **T-Pot** — Multi-honeypot orchestration framework
- **Cowrie** — SSH/Telnet honeypot (command capture)
- **Suricata** — Network IDS/IPS (CVE and signature detection)
- **Kibana** — Dashboard visualisation of attack data
- **Elasticsearch + Logstash** — Log ingestion and storage
- **Hybrid Analysis** — Malware sandbox for binary analysis
- **Wireshark** — Network packet analysis

---

> *Part of MSc Applied Cybersecurity research at Technological University Dublin.*
---

## 📁 Repository Structure
