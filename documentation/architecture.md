# SecureAudit Pro - Architecture & Technical Design

SecureAudit Pro is an automated Web Application Vulnerability Assessment and Penetration Testing (VAPT) SaaS platform engineered for application security specialists, enterprise red teams, and DevSecOps practitioners.

---

## 1. High-Level Architecture

The platform separates user interface, API orchestration, persistent data access, and asynchronous scanning engine execution:

```
[ Frontend: React / Vite / Tailwind / Recharts ]
                      │
                      ▼ HTTP / JSON (JWT Auth)
[ Backend: Django 4.2 / Django REST Framework ]
       │                                │
       ▼                                ▼
[ Persistence: MongoDB (PyMongo) ]   [ Task Queue: Redis & Celery ]
                                                │
                                                ▼
                             [ Master Scan Dispatcher (15 Stages) ]
                                                │
       ┌────────────────────────────────────────┼───────────────────────────────────┐
       ▼                                        ▼                                   ▼
[ Native Python VAPT Engine ]        [ OWASP ZAP Adapter ]                 [ Nuclei Adapter ]
 - HTTP Security Headers              - Headless Daemon API                 - Safe Curated Templates
 - SSL/TLS Handshake & Ciphers        - Automated Spidering                 - CVEs & Misconfigurations
 - Cookie Attributes & Flags          - Passive Alert Collection            - Rate Limit Enforced
 - CORS Trust Policies                - Session Orchestration
 - DNS SPF/DMARC Records
 - Technology Fingerprinting
 - Safe Exposed File Probing
 - OWASP Top 10:2025 Modules
 - OWASP API Security Modules
```

---

## 2. Scanning Engine & Adapter Pattern

All security scanners adhere to the abstract base interface `BaseScannerAdapter`:

- `initialize()`: Assesses connectivity to local or containerized scanning tools.
- `validate_scope()`: Checks whether the target is in the verified organization scope and blocks private IP / SSRF ranges.
- `configure()`: Configures crawl depth, request timeouts, and rate limits.
- `execute()`: Runs security checks, reporting progress via callbacks to the live event stream.
- `collect_results()`: Gathers raw scanner alert outputs.
- `normalize_results()`: Converts alert dictionaries to the canonical SecureAudit Pro schema.
- `stop()`: Aborts background scans cleanly.
- `cleanup()`: Purges temporary data and connections.

---

## 3. Data Storage & Multi-Tenancy

Data is isolated by `organization_id` across MongoDB collections:
- `users`: Analyst accounts with PBKDF2-hashed passwords and RFC 6238 TOTP secrets.
- `websites`: Registered targets with verification status and challenge tokens.
- `scan_jobs`: Execution metadata, stage markers, progress percentage, and timestamps.
- `scan_events`: Fine-grained timestamped log messages displayed in the live console.
- `vulnerabilities`: Deduplicated findings indexed by SHA-256 fingerprint hash (`dedup_key`).
- `remediation_tasks`: Remediation assignments, priority ratings, and verification states.
- `reports`: Generated executive/detailed PDF and exported report metadata.
- `audit_logs`: Immutable security audit events.
