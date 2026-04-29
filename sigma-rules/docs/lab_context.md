# Lab Context

## Environment

These Sigma rules were written and validated against attack traffic
generated in a personal home lab environment consisting of two
virtual machines running on UTM (Apple Silicon):

- **Defender/Target:** Ubuntu 22.04 (aarch64)
- **Attacker:** Kali Linux (aarch64)

## Security Stack

The target machine ran the following security tools during testing:

- **DVWA** — deliberately vulnerable web application used as the
  attack surface for SQL injection testing
- **Cowrie** — SSH honeypot capturing brute force attempts
- **ModSecurity + OWASP CRS** — web application firewall monitoring
  HTTP traffic
- **ELK Stack** — Elasticsearch, Logstash, Kibana, and Filebeat
  used to collect, ship, and visualise all attack logs in real time

## Attacks Simulated

| Tool | Technique | MITRE Technique |
|------|-----------|-----------------|
| Hydra | SSH brute force — username and password spray | T1110.001 |
| Nmap | Network port scanning | T1046 |
| sqlmap | SQL injection via HTTP parameters | T1190 |

## Notes

- All rules are marked `experimental` — they have been validated
  against lab traffic but not production environments
- Thresholds were chosen to balance detection sensitivity against
  false positive rate in a controlled lab setting
- Rules should be tuned to match the specific environment before
  deploying in production
