# Project 1 — Network Attack Detection & Reporting

## Objective
Deploy a Cowrie SSH honeypot, simulate attacks from Kali Linux, and document findings.

## Tools Used
- Cowrie SSH Honeypot (Ubuntu)
- Nmap 7.95 (Kali)
- Wireshark / tcpdump
- iptables

## Environment
- Attacker: Kali Linux — 172.20.10.9
- Target: Ubuntu Cowrie Honeypot — 172.20.10.7

## Files
- `Security_Incident_Report_Portfolio.docx` — Full incident report
- `cowrie_nmap.nmap` — Nmap scan results
- `cowrie_capture.pcap` — Wireshark packet capture
- `screenshot.png` — Honeypot running

## Key Findings
- Port 22 open — SSH intercepted by Cowrie
- Nmap fingerprinted by HASSH analysis
- Brute force login succeeded with weak credentials (root/12345)
- 183 second interactive session fully logged
