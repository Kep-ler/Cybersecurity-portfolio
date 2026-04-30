# Cybersecurity Portfolio

A collection of hands-on security labs and projects completed as part
of my cybersecurity studies. Each project covers a different area of
offensive and defensive security.

---

## Projects

### 1. Network Attack Detection & Reporting
Deployed a Cowrie SSH honeypot on Ubuntu, performed Nmap reconnaissance
and SSH brute force from Kali Linux, captured network traffic with
Wireshark, and documented all findings in a professional incident report.

**Tools:** Cowrie · Nmap · Wireshark · iptables · Kali Linux

[View Project](https://github.com/serra-valle/Cybersecurity-portfolio/blob/main/project-1-honeypot)

---

### 2. Full Security Stack Lab
Built a complete offensive and defensive security environment from scratch.
Deployed DVWA, Cowrie SSH honeypot, ModSecurity WAF with OWASP CRS, and
ELK Stack for centralised log monitoring. Simulated attacks from Kali Linux
using Nmap, sqlmap, and Metasploit. All attack activity monitored and
correlated in Kibana. Deliverables included a network diagram, incident
response report, and technical challenges document.

**Tools:** DVWA · Cowrie · ModSecurity · OWASP CRS · ELK Stack ·
Filebeat · Kibana · Nmap · sqlmap · Metasploit · Kali Linux

---

### 3. Sigma Detection Rules
Four MITRE ATT&CK-mapped Sigma detection rules written from hands-on
attack simulation. Each rule was derived from real log evidence observed
during lab work — not copied from existing rule sets. Covers three
distinct phases of an attack chain.

| Rule | Tactic | Technique | Level |
|------|--------|-----------|-------|
| [SSH Brute Force](sigma-rules/rules/credential_access/ssh_brute_force.yml) | Credential Access | T1110.001 | High |
| [Network Port Scan](sigma-rules/rules/discovery/nmap_port_scan.yml) | Discovery | T1046 | Medium |
| [SQL Injection Attempt](sigma-rules/rules/initial_access/sql_injection_attempt.yml) | Initial Access | T1190 | High |
| [Phishing Malicious Attachment](sigma-rules/rules/initial_access/phishing_malicious_attachment.yml) | Initial Access | T1566.001 | High |

[View Sigma Rules](sigma-rules/README.md)

---

## Skills

- Linux system administration — Ubuntu, Kali
- Web application security — SQLi, XSS, WAF configuration
- Honeypot deployment and network traffic analysis
- SIEM — ELK Stack, Filebeat, Kibana
- Detection engineering — Sigma rules, MITRE ATT&CK mapping
- Offensive tooling — Nmap, Metasploit, sqlmap, Hydra
- Incident response documentation
- Virtualisation — UTM (Apple Silicon)

---

---

## Author

**Adigun** — Cyber Security Analyst  
[LinkedIn](https://www.linkedin.com/in/olamilekan-adigun/) ·
