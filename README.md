# 🛡️ CyberOps Incident Response Playbooks

[![CyberOps](https://img.shields.io/badge/Cisco-CyberOps_Associate-1BA0D7?style=for-the-badge&logo=cisco)](https://www.cisco.com/)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)](https://attack.mitre.org/)
[![NIST](https://img.shields.io/badge/NIST-SP_800--61-blue?style=for-the-badge)](https://csrc.nist.gov/)

> **Incident response playbooks, detection rules, and forensic procedures** based on Cisco CyberOps Associate certification, NIST SP 800-61, and MITRE ATT&CK framework.

---

## 🎓 Certification
**CyberOps Associate** — Cisco Networking Academy

---

## 📂 Structure
```
12-CyberOps-Incident-Response/
├── playbooks/
│   ├── 01-phishing-response.md
│   ├── 02-malware-infection.md
│   ├── 03-ransomware-response.md
│   ├── 04-data-breach.md
│   ├── 05-ddos-mitigation.md
│   ├── 06-insider-threat.md
│   └── 07-brute-force-detection.md
├── scripts/
│   ├── ioc-extractor.py
│   ├── log-parser.py
│   ├── hash-checker.py
│   └── pcap-analyzer.py
├── evidence-templates/
│   ├── chain-of-custody.md
│   ├── incident-report-template.md
│   └── timeline-template.md
└── docs/
    ├── nist-ir-lifecycle.md
    ├── mitre-attack-mapping.md
    └── soc-analyst-runbook.md
```

## 🔄 NIST Incident Response Lifecycle

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  PREPARATION │───→│  DETECTION & │───→│ CONTAINMENT  │───→│   POST-      │
│              │    │  ANALYSIS    │    │ ERADICATION  │    │   INCIDENT   │
│ • Policies   │    │ • SIEM alerts│    │ • Isolate    │    │ • Lessons    │
│ • Tools      │    │ • IOC match  │    │ • Remove     │    │ • Report     │
│ • Training   │    │ • Triage     │    │ • Recover    │    │ • Improve    │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

## 🎯 MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|-------------------|
| Initial Access | Phishing (T1566), Valid Accounts (T1078) |
| Execution | PowerShell (T1059.001), User Execution (T1204) |
| Persistence | Registry Run Keys (T1547), Scheduled Task (T1053) |
| Defense Evasion | Obfuscation (T1027), Disable AV (T1562) |
| Credential Access | Brute Force (T1110), Credential Dumping (T1003) |
| Lateral Movement | RDP (T1021.001), SMB (T1021.002) |
| Exfiltration | HTTP (T1048), DNS Tunneling (T1048.003) |
| Impact | Ransomware (T1486), DDoS (T1498) |

## 📝 Author
**José Carol Lemus Reyes** | CyberOps Associate (Cisco)
