# SecureAudit Pro

**Discover Vulnerabilities. Strengthen Security. Protect Your Digital Assets.**

SecureAudit Pro is a production-grade Web Application Vulnerability Assessment and Penetration Testing (VAPT) SaaS platform designed for application security engineers, enterprise penetration testers, and DevSecOps teams.

Inspired by industry-standard tooling (OWASP ZAP, Burp Suite, Invicti, Acunetix, Pentest-Tools), SecureAudit Pro delivers automated multi-engine security audits, 15-stage real-time progress monitoring, evidence-based vulnerability intelligence, and executive-ready security assessment reports.

---

## 1. Core Platform Features

- **Multi-Engine Scanning Architecture:**
  - **Native Python VAPT Engine:** Comprehensive checks for HTTP security headers (CSP, HSTS, XFO, etc.), SSL/TLS handshake & ciphers, cookie flags, CORS policies, DNS records (SPF, DMARC, DKIM hints, takeover detection), technology fingerprinting, and safe exposed resource detection (`.env`, `.git/HEAD`, backups, dumps).
  - **OWASP Top 10:2025 Modules:** Comprehensive detection rules for all categories A01 through A10.
  - **OWASP API Security Top 10:2023 Modules:** BOLA indicators, broken authentication, unrestricted pagination/resource consumption, and schema disclosure.
  - **OWASP ZAP Automation Framework Adapter:** Headless automated spidering, passive alert collection, and controlled active scanning.
  - **Nuclei Scanner Adapter:** Curated safe community templates with automated rate limiting and DoS exclusion.
- **Strict Scanner Safety Controls:**
  - Explicit domain authorization enforcement (DNS TXT challenge / HTTP challenge).
  - Automated SSRF & IP boundary guard blocking loopback (`127.0.0.0/8`, `::1`), RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and AWS/cloud metadata (`169.254.169.254`).
  - Safe, non-destructive validation probes only.
  - Emergency scan cancellation and pause/resume support.
- **Real-Time Live Monitoring:**
  - 15-stage progressive execution pipeline with live percentage and state tracker.
  - Terminal event stream logging timestamped scan events.
  - Live discovered findings feed.
- **Vulnerability Management & Deduplication:**
  - SHA-256 fingerprint hashing (`dedup_key`) based on target, defect type, and endpoint.
  - CVSS v3.1 / v4.0 scoring and CWE taxonomy mapping.
  - Lifecycle tracking: `Open`, `Confirmed`, `In Progress`, `Fixed`, `Accepted Risk`, `False Positive`, `Reopened`.
  - Analyst discussion threads and retest verification workflows.
- **Remediation & Side-by-Side Comparison:**
  - Assignable remediation tickets with priority levels and due dates.
  - Scan comparison module displaying new findings, fixed findings, persistent defects, and posture score changes.
- **Professional Reporting Engine:**
  - Consulting-grade detailed PDF reports with cover page, executive summaries, and reproduction steps.
  - Responsive standalone HTML reports.
  - Machine-readable JSON exports and CSV vulnerability sheets.
- **Modern Security Operations Center (SOC) Aesthetic:**
  - Dark Navy (`#0B0F19`), Deep Charcoal (`#111827`), Electric Cyan (`#06B6D4`), and Violet accents.
  - Interactive Recharts (Severity Donut, OWASP radar/bar chart, Security Score Gauge).
  - 10 real-time overview metrics calculated dynamically from database records.

---

## 2. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React 18, Vite, TypeScript, Tailwind CSS, Lucide Icons, Recharts, Framer Motion, Axios |
| **Backend API** | Python 3.11, Django 4.2, Django REST Framework, SimpleJWT, Celery, Redis |
| **Database** | MongoDB (via PyMongo with transparent mongomock fallback for local zero-dependency testing) |
| **Scanning** | Native Python Security Probes, OWASP ZAP Automation Framework, Nuclei (Safe Templates) |
| **Reporting** | WeasyPrint, ReportLab, HTML5, CSV, JSON |
| **Infrastructure** | Docker, Docker Compose, Nginx, Gunicorn, Ubuntu 22.04 LTS |

---

## 3. Directory Layout

```
secureaudit-pro/
├── backend/
│   ├── manage.py
│   ├── pytest.ini
│   ├── config/              # Django settings, URLs, Celery, ASGI/WSGI
│   ├── core/                # PyMongo DAL, SSRF security, scoring formula, JWT & RBAC
│   ├── apps/
│   │   ├── authentication/  # User registration, login, JWT, TOTP 2FA, profile
│   │   ├── organizations/   # Multi-tenant organizations & members
│   │   ├── websites/        # Target assets, DNS/HTTP verification challenges
│   │   ├── scanning/        # Scan creation, live event streaming, scan comparison
│   │   ├── vulnerabilities/ # Findings catalog, comments, deduplication, retesting
│   │   ├── remediation/     # Fix tasks, assignees, deadlines, verification
│   │   ├── reports/         # PDF, HTML, JSON, CSV generator & downloader
│   │   ├── administration/  # System health, audit logs, scanner manager, demo reset
│   │   ├── notifications/   # In-app security alerts
│   ├── security_engine/
│   │   ├── base.py          # Abstract Base Scanner Adapter
│   │   ├── dispatcher.py    # 15-stage master pipeline orchestrator
│   │   ├── adapters/        # Native, OWASP ZAP, Nuclei adapters
│   │   ├── checks/          # Headers, SSL/TLS, Cookies, CORS, DNS, Tech, Files, Top 10, API
│   ├── tasks/               # Celery scan and scheduling tasks
│   ├── fixtures/            # Demo data seeder with synthetic real-world assets
│   └── tests/               # Pytest suite for security, auth, and scoring
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── index.html
│   ├── src/
│   │   ├── App.tsx          # Router and protected routes
│   │   ├── types/           # Strongly-typed TypeScript interfaces
│   │   ├── services/        # API client modules
│   │   ├── contexts/        # AuthContext and session state
│   │   ├── charts/          # SeverityDonut, OwaspChart, SecurityScoreGauge
│   │   ├── components/      # Sidebar, TopNavbar, Badges, Modals
│   │   └── pages/           # Landing, Login, Dashboard, Websites, Scans, Vulns, Reports, etc.
├── docker/                  # Dockerfiles and Nginx configuration
├── documentation/           # Architecture, API, Deployment, Security, User Guide
├── scripts/                 # Setup scripts for Linux & Windows, demo seeder
├── docker-compose.yml       # Production 8-service Docker Compose
├── .env.example
└── requirements.txt
```

---

## 4. Quick Start & Installation

### Option A: Running with Docker Compose (Recommended for Production)

```bash
# Clone the repository
git clone https://github.com/organization/secureaudit-pro.git
cd secureaudit-pro

# Configure environment variables
cp .env.example .env

# Start all services
docker compose up -d --build

# Inspect running containers
docker compose ps
```

Access the web UI at `http://localhost`.

---

### Option B: Local Development Setup

#### 1. Backend Setup
```bash
cd backend
python -m venv venv
# On Windows: venv\Scripts\activate | On Linux/macOS: source venv/bin/activate
pip install -r ../requirements.txt

# Run system checks and automated tests
python manage.py check
pytest tests/test_platform.py -v

# Start Django development server
python manage.py runserver 8000
```

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Access the frontend development interface at `http://localhost:3000`.

---

## 5. Demonstration Login Credentials

The application is pre-seeded with 4 standard personas:

| Role | Email | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Security Analyst** | `analyst@secureaudit.pro` | `Analyst@SecureAudit2026!` | Add websites, launch scans, review findings, add comments, assign remediation |
| **Super Administrator** | `admin@secureaudit.pro` | `Admin@SecureAudit2026!` | Full global platform administration, system health, audit logs, reset demo |
| **Organization Admin** | `orgadmin@secureaudit.pro` | `OrgAdmin@SecureAudit2026!` | Manage organization members, target websites, schedules, organization reports |
| **Read-Only Auditor** | `auditor@secureaudit.pro` | `Auditor@SecureAudit2026!` | View-only access to dashboard, completed scans, findings, and reports |

*Note: On the login screen, 1-click quick fill buttons are provided for instant evaluation.*

---

## 6. Testing Results

All core backend security controls, SSRF protections, hashing algorithms, JWT handling, deduplication keys, and scoring formulas have passed automated test suites:

```
======================== 7 passed, 2 warnings in 1.93s ========================
tests/test_platform.py::test_password_hashing PASSED                     [ 14%]
tests/test_platform.py::test_jwt_tokens PASSED                           [ 28%]
tests/test_platform.py::test_totp_generation_and_verification PASSED     [ 42%]
tests/test_platform.py::test_ssrf_protection_blocks_private_and_cloud_ips PASSED [ 57%]
tests/test_platform.py::test_vulnerability_dedup_key PASSED              [ 71%]
tests/test_platform.py::test_security_scoring_formula PASSED             [ 85%]
tests/test_platform.py::test_html_report_rendering PASSED                [100%]
```

The frontend builds cleanly into static production assets:
```
✓ 2162 modules transformed.
dist/index.html                   1.15 kB │ gzip:   0.67 kB
dist/assets/index-D1RF4DMY.css   29.02 kB │ gzip:   5.97 kB
dist/assets/index-CaV4AflA.js   776.14 kB │ gzip: 214.13 kB
✓ built in 11.81s
```

---

## 7. Security Scoring Methodology

The Security Score ranges from **0 to 100** and is calculated as:

$$\text{Score} = \max\left(0, 100 - \sum (\text{SeverityWeight} \times \text{Confidence} \times \text{StatusMultiplier} \times \text{CriticalityFactor})\right)$$

- **Severity Deductions:** Critical (25 pts), High (12 pts), Medium (5 pts), Low (1.5 pts), Info (0.2 pts).
- **Status Multipliers:** Open/Confirmed/Reopened (1.0), In Progress (0.8), Fixed / False Positive (0.0).
- **Disclaimer:** A score of 100 indicates zero automated findings detected within the authorized scope; it does *not* constitute a formal guarantee or certification of complete security.

---

## 8. Implemented & Future Roadmap Features

- [x] Full Role-Based Access Control (RBAC) with JWT and TOTP 2FA.
- [x] Domain verification challenges (DNS TXT, HTTP file, admin override).
- [x] SSRF and Private IP blocking gate.
- [x] 15-stage real-time scan dispatcher and progress tracking.
- [x] Native Python checks for Headers, SSL/TLS, Cookies, CORS, DNS, Exposed Files.
- [x] OWASP Top 10:2025 and OWASP API Security Top 10 modules.
- [x] OWASP ZAP Automation Framework and Nuclei safe template adapters.
- [x] Vulnerability deduplication hashing and status workflow.
- [x] Remediation tracking tickets and automated status synchronization.
- [x] Side-by-side historical scan comparison with score delta.
- [x] Consulting-grade PDF, HTML, JSON, and CSV report generator.
- [x] SOC-grade dark theme UI with animated KPI cards and Recharts.
- [x] Docker Compose with 8 services.
