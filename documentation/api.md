# SecureAudit Pro - REST API Specification

The SecureAudit Pro backend exposes a REST API authenticated using JWT Bearer tokens in the `Authorization: Bearer <token>` header.

---

## 1. Authentication (`/api/auth/`)

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register/` | Register new analyst account | Public |
| `POST` | `/api/auth/login/` | Authenticate user & return JWT tokens | Public |
| `POST` | `/api/auth/refresh/` | Refresh expired access token | Public |
| `GET` | `/api/auth/profile/` | Retrieve current user profile | Authenticated |
| `PUT` | `/api/auth/profile/` | Update user identity fields | Authenticated |
| `POST` | `/api/auth/change-password/` | Change password with current credential verification | Authenticated |
| `POST` | `/api/auth/2fa/setup/` | Generate TOTP secret & QR string | Authenticated |
| `POST` | `/api/auth/2fa/verify/` | Validate 6-digit TOTP code and enable 2FA | Authenticated |
| `GET` | `/api/auth/users/` | List organization users | Org Admin / Super Admin |

---

## 2. Target Websites (`/api/websites/`)

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/websites/` | List registered websites in organization | Read-Only |
| `POST` | `/api/websites/` | Register a new target website | Security Analyst |
| `GET` | `/api/websites/{id}/` | Inspect target details & vulnerability stats | Read-Only |
| `PUT` | `/api/websites/{id}/` | Update target metadata & excluded paths | Security Analyst |
| `DELETE` | `/api/websites/{id}/` | Delete target website | Security Analyst |
| `POST` | `/api/websites/{id}/verify/` | Verify domain via DNS TXT, HTTP file, or admin override | Security Analyst |

---

## 3. Security Scans (`/api/scans/`)

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/scans/` | List historical and active scans | Read-Only |
| `POST` | `/api/scans/` | Initiate a new security scan | Security Analyst |
| `GET` | `/api/scans/{id}/` | Inspect scan execution state & progress | Read-Only |
| `POST` | `/api/scans/{id}/stop/` | Cancel an in-progress scan | Security Analyst |
| `POST` | `/api/scans/{id}/retry/` | Re-run a failed or finished scan | Security Analyst |
| `GET` | `/api/scans/{id}/events/` | Stream live 15-stage scan logs | Read-Only |
| `GET` | `/api/scans/{id}/results/` | Full scan results, tech stack, and SSL info | Read-Only |
| `POST` | `/api/scans/compare/` | Side-by-side comparison of two scans (diffs) | Read-Only |

---

## 4. Vulnerabilities (`/api/vulnerabilities/`)

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/vulnerabilities/` | Query findings with severity/status filters | Read-Only |
| `GET` | `/api/vulnerabilities/{id}/` | Deep technical finding details & evidence | Read-Only |
| `PATCH` | `/api/vulnerabilities/{id}/` | Update finding status (open, confirmed, fixed, etc.) | Security Analyst |
| `POST` | `/api/vulnerabilities/{id}/comments/` | Add analyst comment or patch note | Security Analyst |
| `POST` | `/api/vulnerabilities/{id}/retest/` | Request automated retest after remediation | Security Analyst |

---

## 5. Reports (`/api/reports/`)

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/reports/` | List generated security reports | Read-Only |
| `POST` | `/api/reports/` | Generate PDF, HTML, JSON, or CSV report | Read-Only |
| `GET` | `/api/reports/{id}/download/` | Download report file with Content-Disposition | Read-Only |

---

## 6. Administration (`/api/admin/`)

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/admin/dashboard/` | High-level platform statistics | Org Admin |
| `GET` | `/api/admin/system-health/` | Service health (MongoDB, Redis, Celery, Storage) | Super Admin |
| `GET` | `/api/admin/audit-logs/` | Query security audit events | Org Admin |
| `POST` | `/api/admin/reset-demo/` | Re-seed demonstration environment | Super Admin |
