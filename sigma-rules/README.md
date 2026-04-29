# Sigma Detection Rules

A collection of Sigma detection rules written and validated against
real attack traffic in a personal cybersecurity home lab.

Each rule maps to a MITRE ATT&CK technique and was derived from
hands-on attack simulation — not copied from existing rule sets.

## Rules

| Rule | Tactic | Technique | Level |
|------|--------|-----------|-------|
| [SSH Brute Force](rules/credential_access/ssh_brute_force.yml) | Credential Access | T1110.001 | High |
| [Network Port Scan](rules/discovery/nmap_port_scan.yml) | Discovery | T1046 | Medium |
| [SQL Injection Attempt](rules/initial_access/sql_injection_attempt.yml) | Initial Access | T1190 | High |

## Lab Environment

Rules were validated against attack traffic generated in a home lab:

- **Target:** Ubuntu 22.04 on UTM (Apple Silicon)
- **Attacker:** Kali Linux on UTM (Apple Silicon)
- **Security stack:** DVWA, Cowrie, ModSecurity + OWASP CRS, ELK Stack
- **Attack tools:** Hydra, Nmap, sqlmap

Full environment details in [docs/lab_context.md](docs/lab_context.md)

## Rule Coverage

```
Reconnaissance     → Nmap port scan detection
Initial Access     → SQL injection attempt detection  
Credential Access  → SSH brute force detection
```

These three rules cover three distinct phases of an attack chain —
from the first probe to the credential attack.

## How These Were Written

Each rule followed the same methodology:

1. Simulate the attack in the lab
2. Identify the exact log evidence the attack produced
3. Define a threshold separating attack behaviour from normal activity
4. Map to MITRE ATT&CK
5. Document known false positives

## Author

**Adigun** — Cyber Security Analyst  
CompTIA Security+ certified
