# 📋 Findings Summary — T-Pot Honeypot Analysis

**MSc Applied Cybersecurity | Technological University Dublin**
**Observation Period:** ~2 months | **Total Attacks:** 2,000,000+

---

## 1. Key Statistics

| Metric | Value |
|---|---|
| Total attacks captured | 2,000,000+ |
| Observation period | ~2 months |
| Honeypot platform | T-Pot (Deutsche Telekom) |
| Cloud host | DigitalOcean (Ubuntu 22.04 LTS) |
| Highest-volume honeypot | Honeytrap (~600,000 attacks) |
| Most targeted port | 5060 (VoIP/SIP) |
| Second most targeted port | 22 (SSH) |
| Attacks from known malicious IPs | 1,068,897 |
| Attacks from mass scanners | 31,083 |
| Top attacker ASN | AS47890 — Unmanaged Ltd (310,165 attacks) |
| Malware families confirmed | 3 (Mirai, Tsunami, Backdoor:Linux) |

---

## 2. Attack Distribution by Honeypot

| Honeypot | Type | Approx. Attacks | Purpose |
|---|---|---|---|
| Honeytrap | Dynamic multi-port | ~600,000 | Captures exploitation attempts across open ports |
| Cowrie | SSH/Telnet medium interaction | High | Records full attacker command sessions |
| Sentrypeer | P2P VoIP/SIP | High | Detects SIP brute-force attacks |
| Dionaea | Malware capture | Moderate | Collects malware samples via service emulation |

---

## 3. Geographic Distribution

| Rank | Country | Notes |
|---|---|---|
| 1 | United States | Primarily cloud infrastructure abuse |
| 2 | Romania | Significant share of known malicious IPs |
| 3 | Netherlands | Hosting provider abuse |
| 4 | Ukraine | SSH-focused scanners |
| 5 | France | Mixed scanning activity |

Key Insight: Attacks originate globally, demonstrating the international and automated nature of modern threat actors. Attackers leverage cloud and hosting infrastructure to scale attacks while obscuring identity.

---

## 4. IP Reputation Analysis

| Category | Count |
|---|---|
| Known malicious IPs | 1,068,897 |
| Mass scanners | 31,083 |
| Tor exit nodes | Low |
| Spam/crawlers | Low |

Key Insight: The majority of attacks came from IPs with an established history of malicious behaviour — reinforcing the value of threat intelligence feed integration for proactive blocking.

---

## 5. Malware Families Identified

### Mirai
- Type: IoT Botnet
- Behaviour: Brute-forces SSH/Telnet (ports 22/23), deploys architecture-specific ELF binaries, turns devices into DDoS bots
- C2 Method: Hardcoded IPs and ports
- Architecture Support: ARM, MIPS, x86, PowerPC
- Confirmed via: Hybrid Analysis sandbox

### Tsunami
- Type: DDoS Botnet + Backdoor
- Behaviour: Provides remote shell access, executes attacker commands, performs large-scale DDoS attacks
- C2 Method: IRC-based Command and Control
- Confirmed via: Hybrid Analysis sandbox + Cowrie command logs

### Backdoor:Linux (Generic ELF RAT)
- Type: Remote Access Trojan
- Behaviour: Remote command execution, system modification, persistence installation, additional payload download
- C2 Method: TCP-based

---

## 6. MITRE ATT&CK Mapping

| Attack Stage | MITRE Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Brute Force: Password Guessing | T1110.001 | SSH login attempts with credential dictionaries |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Attacker issued Bash commands via Cowrie shell |
| Persistence | SSH Authorized Keys | T1098.004 | wget malicious key to ~/.ssh/authorized_keys |
| Persistence | Create Account | T1136 | daemon backdoor account created |
| Privilege Escalation | Abuse Elevation Control: Sudo | T1548.003 | echo daemon ALL NOPASSWD >> /etc/sudoers |
| Defence Evasion | Masquerade File Type | T1036.007 | ELF binaries disguised as .jpg images |
| Defence Evasion | File Deletion | T1070.004 | rm -f /tmp/o to remove malware traces |
| Discovery | System Information Discovery | T1082 | uname -a, lscpu, df -h |
| Discovery | System Owner/User Discovery | T1033 | id, cat /etc/passwd, cat /etc/shadow |
| Command and Control | Application Layer Protocol: IRC | T1071.003 | Tsunami IRC-based C2 communication |
| Lateral Movement | Remote Services: SSH | T1021.004 | SSH key injection for persistent re-entry |
| Impact | Network Denial of Service | T1498 | Mirai/Tsunami DDoS module execution |
| Resource Development | Ingress Tool Transfer | T1105 | wget/curl used to pull payloads from C2 |

---

## 7. Notable CVEs Detected

| CVE | CVSS | Affected Component | Severity |
|---|---|---|---|
| CVE-2020-11900 | Moderate | Treck TCP/IP stack (< 6.0.1.41) — IPv4 double-free | Medium |
| CVE-2020-11910 | 9.8 Critical | Treck TCP/IP stack — Out-of-bounds Read (CWE-125) | Critical |

Both CVEs target embedded IoT devices, consistent with Mirai's targeting of IoT infrastructure.

---

## 8. Key Conclusions

1. Automated attacks dominate. Over 70% of attacks originated from known malicious IPs, confirming that most threats are automated botnet and scanner activity rather than targeted manual intrusions.

2. IoT remains a primary target. SSH (port 22), Telnet (port 23), and SIP/VoIP (port 5060) were the most targeted services — consistent with Mirai-family botnet propagation patterns.

3. Cloud infrastructure is being weaponised. Major cloud providers (DigitalOcean, Google Cloud, Azure) featured significantly in attacker ASNs, indicating attackers abuse legitimate infrastructure for anonymity and scalability.

4. T-Pot captured a complete infection chain. From brute-force login through to malware delivery, persistence, and payload execution — the full Mirai/Tsunami infection workflow was documented in Cowrie logs.

5. The fake JPG technique is actively used. Disguising ELF binaries as image files is a live evasion technique used to bypass content filtering and signature-based detection.

6. Threat intelligence feeds are essential. The near-total domination of known malicious IPs in the dataset demonstrates that proactive blocking via threat intel feeds would prevent the majority of attacks.

---

## 9. Recommendations

| Category | Recommendation |
|---|---|
| Network Hardening | Disable SSH password auth — use key-based only. Restrict SSH to known IPs or VPN |
| Monitoring | Alert on wget/curl from shell, sudoers modifications, authorized_keys changes |
| Threat Intelligence | Integrate up-to-date threat feed blocking (AbuseIPDB, Emerging Threats) |
| Malware Defence | Sandbox suspicious binaries regardless of file extension |
| Patch Management | Patch Treck TCP/IP stack on embedded devices (CVE-2020-11910 CVSS 9.8) |
| IoT Security | Change default credentials on all internet-facing IoT devices |

---

> Research conducted as part of MSc Applied Cybersecurity at Technological University Dublin.
> Tools used: T-Pot, Cowrie, Suricata, ELK Stack, Kibana, Hybrid Analysis
