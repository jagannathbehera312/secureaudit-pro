"""
SecureAudit Pro - HTTP Security Headers Assessment Module
Analyzes CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
"""

from typing import Dict, Any, List


def analyze_security_headers(headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
    findings = []
    # Normalize headers to lowercase keys
    norm = {k.lower(): v for k, v in headers.items()}

    # 1. Strict-Transport-Security (HSTS)
    hsts = norm.get("strict-transport-security")
    if not hsts:
        findings.append({
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "vuln_type": "missing_hsts",
            "severity": "medium",
            "cvss_score": 5.3,
            "cwe_id": "CWE-319",
            "owasp_category": "A04:2025 - Cryptographic Failures",
            "description": "The HTTP Strict-Transport-Security (HSTS) header is missing. Without HSTS, browsers may allow insecure HTTP connections susceptible to man-in-the-middle (MITM) downgrade attacks.",
            "impact": "Attackers on the same network can intercept unencrypted HTTP traffic and strip SSL via SSLStrip attacks.",
            "remediation": "1. In Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n2. In Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n3. In Django settings.py: SECURE_HSTS_SECONDS = 31536000, SECURE_HSTS_INCLUDE_SUBDOMAINS = True, SECURE_HSTS_PRELOAD = True",
            "evidence": f"Headers checked on {url}. strict-transport-security header was not returned.",
            "affected_url": url,
            "confidence": "confirmed",
            "status": "open"
        })
    elif "max-age" in hsts and "includesubdomains" not in hsts.lower():
        findings.append({
            "title": "HSTS Missing includeSubDomains Directive",
            "vuln_type": "hsts_no_subdomains",
            "severity": "low",
            "cvss_score": 3.1,
            "cwe_id": "CWE-319",
            "owasp_category": "A04:2025 - Cryptographic Failures",
            "description": "HSTS header is configured but does not protect subdomains, allowing potential subdomain hijack or downgrade.",
            "impact": "Subdomains of this target may remain vulnerable to cleartext interception.",
            "remediation": "Append '; includeSubDomains' to the Strict-Transport-Security header value:\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "evidence": f"Header value: {hsts}",
            "affected_url": url,
            "confidence": "confirmed",
            "status": "open"
        })

    # 2. Content-Security-Policy (CSP)
    csp = norm.get("content-security-policy")
    if not csp:
        findings.append({
            "title": "Missing Content-Security-Policy (CSP) Header",
            "vuln_type": "missing_csp",
            "severity": "medium",
            "cvss_score": 6.1,
            "cwe_id": "CWE-1021",
            "owasp_category": "A02:2025 - Security Misconfiguration",
            "description": "Content-Security-Policy (CSP) is an effective defense-in-depth header against Cross-Site Scripting (XSS), data injection, and clickjacking.",
            "impact": "Increases susceptibility to reflected, stored, or DOM-based XSS attacks, as malicious scripts are allowed to execute without origin restrictions.",
            "remediation": "1. Configure a strict Content-Security-Policy header in your reverse proxy:\n   Nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';\" always;\n   Apache: Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\"\n2. In Django: Configure django-csp middleware with CSP_DEFAULT_SRC = (\"'self'\",)\n3. In Node.js / Express: Use helmet.contentSecurityPolicy().",
            "evidence": f"Headers on {url} lacked a content-security-policy header.",
            "affected_url": url,
            "confidence": "confirmed",
            "status": "open"
        })
    else:
        if "'unsafe-inline'" in csp:
            findings.append({
                "title": "Insecure CSP: 'unsafe-inline' Permitted in Directives",
                "vuln_type": "csp_unsafe_inline",
                "severity": "medium",
                "cvss_score": 4.8,
                "cwe_id": "CWE-1021",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "description": "CSP includes 'unsafe-inline', which disables inline script execution protection and severely weakens XSS defenses.",
                "impact": "Attackers who inject inline <script> or event handler tags can execute JavaScript in user browsers.",
                "remediation": "1. Remove 'unsafe-inline' from script-src and style-src.\n2. Implement cryptographic nonces ('nonce-<base64>') or SHA-256 hashes for trusted inline scripts.\n3. Externalize JavaScript into static .js files loaded from 'self'.",
                "evidence": f"CSP Directive: {csp}",
                "affected_url": url,
                "confidence": "confirmed",
                "status": "open"
            })
        if "'unsafe-eval'" in csp:
            findings.append({
                "title": "Insecure CSP: 'unsafe-eval' Permitted in Directives",
                "vuln_type": "csp_unsafe_eval",
                "severity": "low",
                "cvss_score": 3.7,
                "cwe_id": "CWE-1021",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "description": "CSP permits 'unsafe-eval', allowing dynamic code evaluation via eval() or Function constructors.",
                "impact": "Increases attack surface if any injection sink feeds into eval/template execution.",
                "remediation": "1. Refactor frontend code to eliminate eval(), setTimeout(string), and new Function().\n2. Remove 'unsafe-eval' from the script-src directive in your Content-Security-Policy.",
                "evidence": f"CSP Directive: {csp}",
                "affected_url": url,
                "confidence": "confirmed",
                "status": "open"
            })

    # 3. X-Frame-Options (Clickjacking defense)
    xfo = norm.get("x-frame-options")
    if not xfo and (not csp or "frame-ancestors" not in csp):
        findings.append({
            "title": "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
            "vuln_type": "missing_clickjacking_protection",
            "severity": "medium",
            "cvss_score": 5.4,
            "cwe_id": "CWE-1021",
            "owasp_category": "A02:2025 - Security Misconfiguration",
            "description": "Neither X-Frame-Options nor CSP frame-ancestors is present. The page can be embedded into an attacker's iframe, leading to Clickjacking (UI redressing).",
            "impact": "Attackers can trick users into performing unauthorized actions by overlaying deceptive visual elements over the legitimate application.",
            "remediation": "1. In Nginx: add_header X-Frame-Options \"DENY\" always;\n2. In Apache: Header always set X-Frame-Options \"DENY\"\n3. In Django settings.py: X_FRAME_OPTIONS = 'DENY'\n4. Or specify CSP: Content-Security-Policy: frame-ancestors 'none';",
            "evidence": f"No X-Frame-Options header or CSP frame-ancestors found on {url}",
            "affected_url": url,
            "confidence": "confirmed",
            "status": "open"
        })

    # 4. X-Content-Type-Options
    xcto = norm.get("x-content-type-options")
    if not xcto or "nosniff" not in xcto.lower():
        findings.append({
            "title": "Missing X-Content-Type-Options: nosniff Header",
            "vuln_type": "missing_xcto",
            "severity": "low",
            "cvss_score": 3.4,
            "cwe_id": "CWE-16",
            "owasp_category": "A02:2025 - Security Misconfiguration",
            "description": "The X-Content-Type-Options header is absent or not set to 'nosniff'. Browsers may attempt MIME-sniffing, treating non-executable MIME types as executable.",
            "impact": "Can allow user-uploaded files (e.g. images) containing script payloads to be interpreted as HTML/JavaScript.",
            "remediation": "1. In Nginx: add_header X-Content-Type-Options \"nosniff\" always;\n2. In Apache: Header always set X-Content-Type-Options \"nosniff\"\n3. In Django settings.py: SECURE_CONTENT_TYPE_NOSNIFF = True\n4. In Express.js: app.use(helmet.noSniff());",
            "evidence": f"Received x-content-type-options: {xcto or 'None'}",
            "affected_url": url,
            "confidence": "confirmed",
            "status": "open"
        })

    # 5. Referrer-Policy
    referrer = norm.get("referrer-policy")
    if not referrer or referrer.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append({
            "title": "Missing or Weak Referrer-Policy Header",
            "vuln_type": "weak_referrer_policy",
            "severity": "low",
            "cvss_score": 2.6,
            "cwe_id": "CWE-116",
            "owasp_category": "A02:2025 - Security Misconfiguration",
            "description": "The Referrer-Policy header is missing or configured with a weak policy that leaks URLs and query parameters to third-party domains.",
            "impact": "Sensitive session tokens, reset hashes, or internal IDs in URL query parameters can leak to external analytics or linked sites.",
            "remediation": "1. In Nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n2. In Apache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n3. In Django settings.py: SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'\n4. In Express.js: app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
            "evidence": f"Received referrer-policy: {referrer or 'None'}",
            "affected_url": url,
            "confidence": "confirmed",
            "status": "open"
        })

    # 6. Permissions-Policy
    perm = norm.get("permissions-policy")
    if not perm:
        findings.append({
            "title": "Missing Permissions-Policy Header",
            "vuln_type": "missing_permissions_policy",
            "severity": "info",
            "cvss_score": 1.5,
            "cwe_id": "CWE-16",
            "owasp_category": "A02:2025 - Security Misconfiguration",
            "description": "The Permissions-Policy header allows web developers to restrict browser features and APIs (geolocation, camera, microphone, payment).",
            "impact": "Third-party embedded scripts or iframes could potentially request hardware or browser permissions without restrictions.",
            "remediation": "1. In Nginx: add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always;\n2. In Apache: Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\"\n3. In Django: Set header in custom middleware or reverse proxy.",
            "evidence": f"Headers on {url} lacked permissions-policy header.",
            "affected_url": url,
            "confidence": "confirmed",
            "status": "open"
        })

    # 7. Information Leakage via Server & Powered-By Headers
    server = norm.get("server")
    powered_by = norm.get("x-powered-by")
    aspnet = norm.get("x-aspnet-version")
    
    leakage_details = []
    if server and any(char.isdigit() for char in server):
        leakage_details.append(f"Server banner discloses version: {server}")
    if powered_by:
        leakage_details.append(f"X-Powered-By discloses runtime: {powered_by}")
    if aspnet:
        leakage_details.append(f"X-AspNet-Version discloses framework: {aspnet}")

    if leakage_details:
        findings.append({
            "title": "Server Software Version Information Disclosure",
            "vuln_type": "server_version_disclosure",
            "severity": "low",
            "cvss_score": 3.8,
            "cwe_id": "CWE-200",
            "owasp_category": "A02:2025 - Security Misconfiguration",
            "description": "HTTP response headers disclose exact web server, runtime, or framework software versions.",
            "impact": "Provides automated vulnerability scanners and malicious actors with exact version numbers to target known CVEs.",
            "remediation": "1. In Nginx: Add 'server_tokens off;' in the http block of /etc/nginx/nginx.conf.\n2. In Apache: Set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf.\n3. In Express.js: app.disable('x-powered-by'); or use helmet.hidePoweredBy();\n4. In PHP: Set 'expose_php = Off' in php.ini.",
            "evidence": "; ".join(leakage_details),
            "affected_url": url,
            "confidence": "confirmed",
            "status": "open"
        })

    return findings
