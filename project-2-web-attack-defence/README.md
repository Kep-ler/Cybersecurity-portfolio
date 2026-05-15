# Project 2 — Attack and Defend Web Application

## Overview

| Field | Details |
|---|---|
| **Objective** | Perform and block web-based attacks on DVWA and PrestaShop |
| **Date** | March 14, 2026 |
| **Attacker** | Kali Linux — 172.20.10.9 |
| **Target** | Ubuntu 24.04 — 172.20.10.7 |
| **Tools** | sqlmap · dirb · Hydra · Firefox · ModSecurity · OWASP CRS |

---

## Lab Architecture

```
┌─────────────────────┐         ┌──────────────────────────────────┐
│   Kali Linux VM     │ ──────► │         Ubuntu 24.04 VM          │
│   172.20.10.9       │  HTTP   │         172.20.10.7              │
│                     │  SSH    │                                  │
│  Tools:             │         │  Running:                        │
│  - Firefox          │         │  - Apache 2.4.58                 │
│  - dirb             │         │  - DVWA (PHP/MariaDB)            │
│  - Hydra 9.5        │         │  - PrestaShop 9.0.3              │
│  - sqlmap           │         │  - ModSecurity 2.9.7             │
└─────────────────────┘         │  - OWASP CRS 3.3.5               │
                                └──────────────────────────────────┘
```

---

## Part 1 — DVWA Attack and Defence

### Environment
- DVWA running on Ubuntu 24.04 with Apache
- Security level: Low
- All attacks launched from Kali Linux browser

### SQL Injection Attacks

| Attack | Payload | Without WAF | With WAF |
|---|---|---|---|
| Basic SQLi | `' OR '1'='1` | All user records dumped | 403 Blocked |
| DB Version | `' UNION SELECT null,version()#` | MySQL version exposed | 403 Blocked |
| DB Name | `' UNION SELECT null,database()#` | Database name (dvwa) exposed | 403 Blocked |
| Table Names | `' UNION SELECT null,table_name FROM information_schema.tables WHERE table_schema=database()#` | All table names dumped | 403 Blocked |

### XSS Attacks

| Attack | Payload | Without WAF | With WAF |
|---|---|---|---|
| Reflected XSS | `<script>alert('XSS')</script>` | Alert popup fired in browser | 403 Blocked |
| Stored XSS | `<script>alert('Stored XSS')</script>` | Payload stored in DB, fires on every page load | 403 Blocked |

---

## Part 2 — WAF Configuration

### ModSecurity Setup

| Field | Detail |
|---|---|
| **Software** | ModSecurity 2.9.7 |
| **Web Server** | Apache 2.4.58 (Ubuntu) |
| **Rule Set** | OWASP CRS 3.3.5 |
| **Engine Mode** | On (Enforced) |
| **Package** | libapache2-mod-security2 |
| **Config File** | /etc/modsecurity/modsecurity.conf |

### Key Configuration Change
```bash
# Changed from DetectionOnly to enforcement mode
SecRuleEngine On
```

### WAF Validation — Audit Log Evidence
```
Action: Intercepted (phase 2)
Engine-Mode: ENABLED
Producer: ModSecurity for Apache/2.9.7
Rule Set: OWASP_CRS/3.3.5
```
Confirmed in `/var/log/apache2/modsec_audit.log` after all attack testing.

---

## Part 3 — PrestaShop Security Hardening Checklist

### Environment

| Field | Detail |
|---|---|
| **Application** | PrestaShop 9.0.3 |
| **Server** | Apache 2.4.58 on Ubuntu 24.04 |
| **PHP Version** | 8.3.6 |
| **Database** | MariaDB 10.11.14 |
| **Admin Path** | Randomised (admin740oaqd6tpzv7pcpuno) |

### Checklist Results

| # | Item | Status | Action Taken |
|---|---|---|---|
| 1 | Application and Modules Up To Date | ✅ Pass | Updated 4 modules via Module Manager. Increased memory_limit to 256M and max_execution_time to 300 |
| 2 | Remove Default/Demo Accounts and Sample Data | ✅ Pass | Demo accounts and sample data removed |
| 3 | Strong Admin Password and MFA | ⚠️ Partial | Password policy hardened. MFA unavailable natively — IP restriction applied as compensating control |
| 4 | File/Folder Permissions and Directory Listing | ✅ Pass | Options -Indexes added to Apache config. Makefile hardened to 640 |
| 5 | Secure Session Cookie Settings | ✅ Pass | HttpOnly and SameSite=Strict confirmed. Cookie lifetime restricted. IP check enabled |
| 6 | Disable Unnecessary Modules | ✅ Pass | Payment modules and unused modules disabled via Module Manager |
| 7 | Payment and API Endpoint Configuration | ✅ Pass | Webservice disabled. API returns 401 Unauthorized. Payment modules disabled |
| 8 | TLS Configured and Enforced | ❌ Fail (Lab) | Lab limitation — HTTP only. Security headers added as partial mitigation |
| 9 | Exposed Admin Paths and IP Restrictions | ✅ Pass | Admin path randomised. IP restriction applied to 172.20.10.0/28 subnet |
| 10 | Backup and Recovery Verification | ✅ Pass | DB backup via mysqldump. Files backup via tar. Both verified |

### Summary
- **Pass:** 8 / 10
- **Partial:** 1 / 10 (MFA not available natively)
- **Fail:** 1 / 10 (TLS — lab environment limitation)

---

## Part 4 — PrestaShop Attack Simulation

### Methodology
- **Phase 1:** All attacks with ModSecurity in DetectionOnly mode (WAF inactive)
- **Phase 2:** All attacks repeated with ModSecurity On (WAF enforced)
- Evidence collected via screenshots and `/var/log/apache2/modsec_audit.log`

---

### Attack 1 — Directory Enumeration

| Field | Detail |
|---|---|
| **Tool** | dirb |
| **Command** | `dirb http://172.20.10.7 /usr/share/dirb/wordlists/common.txt` |
| **Risk** | Medium |

**Without WAF:** 54 paths discovered including `/api` (401), `/Makefile` (200 — sensitive), `/login` (200), `/upload`, `/modules`, `/webservice`

**With WAF:** 403 Forbidden — ModSecurity intercepted scanning requests

**Log Evidence:**
```
Action: Intercepted (phase 2)
```

**Mitigation:** ModSecurity enforced · Options -Indexes added · Makefile hardened to 640

---

### Attack 2 — XSS via Search Bar

| Field | Detail |
|---|---|
| **Tool** | Firefox browser |
| **Payload** | `<script>alert('XSS')</script>` |
| **Target** | `http://172.20.10.7/search?s=<script>alert('XSS')</script>` |
| **Risk** | Low |

**Without WAF:** No execution — PrestaShop 9 native output escaping encoded the payload as plain text

**With WAF:** 403 Forbidden — ModSecurity blocked before reaching application

**Mitigation:** PrestaShop templating engine (layer 1) · ModSecurity WAF (layer 2)

---

### Attack 3 — SQL Injection via Search

| Field | Detail |
|---|---|
| **Tool** | Firefox browser |
| **Payload** | `' OR '1'='1` |
| **Target** | `http://172.20.10.7/search?s='+OR+'1'='1` |
| **Risk** | Low |

**Without WAF:** No data returned — PrestaShop 9 uses Doctrine ORM with prepared statements preventing raw SQL injection

**With WAF:** 403 Forbidden — ModSecurity blocked before reaching application

**Mitigation:** Doctrine ORM prepared statements (layer 1) · ModSecurity WAF (layer 2)

---

### Attack 4 — Admin Panel Brute Force

| Field | Detail |
|---|---|
| **Tool** | Hydra 9.5 |
| **Username** | admin@testshop.com |
| **Wordlist** | /usr/share/wordlists/rockyou.txt |
| **Risk** | High |

**Command:**
```bash
hydra -l admin@testshop.com -P /usr/share/wordlists/rockyou.txt 172.20.10.7 \
http-post-form "/admin740oaqd6tpzv7pcpuno/index.php:email=^USER^&passwd=^PASS^&submitLogin=1:Invalid" \
-V -f -t 4
```

**Without WAF:** 880+ login attempts made with zero lockout or throttling triggered

**With WAF:** 403 Forbidden — ModSecurity blocked all brute force requests

**Mitigation:** ModSecurity WAF · IP restriction to 172.20.10.0/28 · Recommend account lockout + MFA module

---

### Attack Simulation Summary

| Attack | Without WAF | With WAF | Risk |
|---|---|---|---|
| Directory Enumeration | 54 paths discovered | Blocked | Medium |
| XSS via Search | App-level mitigation prevented | Blocked | Low |
| SQL Injection via Search | App-level mitigation prevented | Blocked | Low |
| Admin Brute Force | 880+ attempts, no lockout | Blocked | High |

---

## Recommendations

| Priority | Recommendation |
|---|---|
| 🔴 High | Enable account lockout and rate limiting on admin login |
| 🔴 High | Implement TLS for any production deployment |
| 🔴 High | Keep ModSecurity enforced — never revert to DetectionOnly in production |
| 🟡 Medium | Enable MFA via third-party PrestaShop module |
| 🟡 Medium | Schedule regular module and core updates |
| 🟡 Medium | Schedule regular automated DB and file backups with offsite storage |
| ✅ Done | Restrict admin path access by IP |
| ✅ Done | Remove/restrict access to sensitive files like Makefile |

---

## Key Takeaways

- ModSecurity with OWASP CRS 3.3.5 successfully blocked **all 4 attack types** when enforced
- DVWA demonstrated how **unprotected applications** are trivially exploitable with basic payloads
- PrestaShop 9's native ORM and templating engine provided **application-level defence** as a first layer
- WAF enforcement provides a **critical second layer** catching attacks before they reach the app
- **Defence in depth** — multiple layers (app hardening + WAF + IP restriction) is more effective than any single control

---

## Files in This Project

| File | Description |
|---|---|
| `README.md` | This report |
| `screenshots/` | Evidence screenshots from all attacks and WAF responses |

---

*Lab environment: Ubuntu 24.04 · Kali Linux · UTM on macOS Apple Silicon*
