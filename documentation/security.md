# SecureAudit Pro - Security Architecture & Scanner Safety Controls

As an offensive and defensive security platform, SecureAudit Pro implements strict security controls to ensure scanners cannot be abused against unauthorized external systems or internal infrastructure.

---

## 1. Scanner Safety Boundary Controls

1. **Domain Authorization Requirement:** Scans cannot be executed against unverified domains. Domain ownership must be verified via:
   - DNS TXT record challenge token (`_secureaudit.<domain>`).
   - HTTP file challenge (`/.well-known/secureaudit-challenge.txt`).
   - Administrator authorization declaration.

2. **Server-Side Request Forgery (SSRF) Protection:**
   - Every target hostname is resolved to all associated IPv4/IPv6 addresses via `socket.getaddrinfo` prior to dispatch.
   - Any address in loopback (`127.0.0.0/8`, `::1`), private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.169.254`), or multicast ranges triggers an immediate security rejection.
   - DNS re-resolution is conducted on HTTP redirects to prevent DNS rebinding attacks.

3. **Non-Destructive Payloads Only:**
   - Injection testing uses benign syntax verification probes (e.g. harmless mathematical evaluations and neutralization checks) without executing operating system shell commands or modifying backend databases.
   - Denial-of-service, brute forcing, password spraying, and resource exhaustion templates are excluded by default.

4. **Emergency Stop Mechanism:**
   - Scan jobs check for cancellation requests at every stage in the 15-stage pipeline, immediately halting execution and terminating child processes.

---

## 2. Platform Authentication & RBAC

1. **Role Hierarchy:**
   - **Super Admin:** Global system settings, user management, engine status, audit logs.
   - **Org Admin:** Manage organization members, target websites, schedules, reports.
   - **Security Analyst:** Register targets, initiate scans, review findings, add comments, assign remediation tasks.
   - **Read-Only Auditor:** View reports, dashboard metrics, and vulnerability catalog without mutation rights.

2. **Cryptographic Protection:**
   - Passwords hashed using PBKDF2-HMAC-SHA256 with 260,000 iterations and cryptographic salts.
   - RFC 6238 TOTP two-factor authentication support.
   - JWT tokens signed with HS256 and 8-hour access token expiration.
