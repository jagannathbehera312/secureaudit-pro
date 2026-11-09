"""
SecureAudit Pro - Cookie Security Assessment Module
Inspects Set-Cookie headers for Secure, HttpOnly, SameSite attributes and scope security.
"""

from typing import List, Dict, Any
from http.cookies import SimpleCookie
import urllib.parse


def analyze_cookies(cookie_headers: List[str], url: str) -> List[Dict[str, Any]]:
    findings = []
    is_https = urllib.parse.urlparse(url).scheme == "https"

    for header_val in cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(header_val)
        except Exception:
            continue

        for name, morsel in cookie.items():
            flags = {k.lower(): v for k, v in morsel.items()}
            is_sensitive = any(kw in name.lower() for kw in ("sess", "auth", "token", "jwt", "id", "admin", "login"))

            # 1. Missing Secure flag
            if is_https and not morsel.get("secure"):
                findings.append({
                    "title": f"Insecure Cookie Flag: Missing 'Secure' on '{name}'",
                    "vuln_type": "cookie_missing_secure",
                    "severity": "medium" if is_sensitive else "low",
                    "cvss_score": 5.4 if is_sensitive else 3.1,
                    "cwe_id": "CWE-614",
                    "owasp_category": "A04:2025 - Cryptographic Failures",
                    "description": f"The cookie '{name}' was set without the 'Secure' attribute on an HTTPS endpoint.",
                    "impact": "The browser may transmit this cookie in unencrypted HTTP requests if a user visits an HTTP link or HTTP resource on this domain.",
                    "remediation": f"1. Append the 'Secure' directive: Set-Cookie: {name}=<val>; Secure;\n2. In Django settings.py: SESSION_COOKIE_SECURE = True, CSRF_COOKIE_SECURE = True\n3. In Node.js / Express: Set cookie: {{ secure: true }} in session configuration\n4. In Nginx reverse proxy: proxy_cookie_flags ~ secure;",
                    "evidence": f"Raw Set-Cookie header: {header_val}",
                    "affected_url": url,
                    "confidence": "confirmed",
                    "status": "open"
                })

            # 2. Missing HttpOnly flag
            if not morsel.get("httponly"):
                findings.append({
                    "title": f"Insecure Cookie Flag: Missing 'HttpOnly' on '{name}'",
                    "vuln_type": "cookie_missing_httponly",
                    "severity": "medium" if is_sensitive else "low",
                    "cvss_score": 5.3 if is_sensitive else 2.6,
                    "cwe_id": "CWE-1004",
                    "owasp_category": "A07:2025 - Authentication Failures",
                    "description": f"The cookie '{name}' lacks the 'HttpOnly' attribute, making it accessible to client-side scripts via document.cookie.",
                    "impact": "If an XSS vulnerability exists on the site, malicious JavaScript can steal this cookie, leading to session hijacking.",
                    "remediation": f"1. Append the 'HttpOnly' directive: Set-Cookie: {name}=<val>; HttpOnly;\n2. In Django settings.py: SESSION_COOKIE_HTTPONLY = True, CSRF_COOKIE_HTTPONLY = True\n3. In Node.js / Express: Set cookie: {{ httpOnly: true }}\n4. In PHP: Set session.cookie_httponly = 1 in php.ini",
                    "evidence": f"Raw Set-Cookie header: {header_val}",
                    "affected_url": url,
                    "confidence": "confirmed",
                    "status": "open"
                })

            # 3. SameSite attribute analysis
            samesite = morsel.get("samesite")
            if not samesite:
                findings.append({
                    "title": f"Missing 'SameSite' Attribute on Cookie '{name}'",
                    "vuln_type": "cookie_missing_samesite",
                    "severity": "low",
                    "cvss_score": 3.7,
                    "cwe_id": "CWE-1275",
                    "owasp_category": "A01:2025 - Broken Access Control",
                    "description": f"The cookie '{name}' does not specify a 'SameSite' attribute.",
                    "impact": "Leaves the application relying on browser defaults and increases exposure to Cross-Site Request Forgery (CSRF).",
                    "remediation": f"1. Explicitly configure 'SameSite=Lax' (recommended for web applications) or 'SameSite=Strict':\n   Set-Cookie: {name}=<val>; SameSite=Lax; Secure; HttpOnly\n2. In Django settings.py: SESSION_COOKIE_SAMESITE = 'Lax'\n3. In Express: cookie: {{ sameSite: 'lax' }}",
                    "evidence": f"Raw Set-Cookie header: {header_val}",
                    "affected_url": url,
                    "confidence": "confirmed",
                    "status": "open"
                })
            elif samesite.lower() == "none" and not morsel.get("secure"):
                findings.append({
                    "title": f"Invalid SameSite=None Without Secure on Cookie '{name}'",
                    "vuln_type": "cookie_samesite_none_insecure",
                    "severity": "medium",
                    "cvss_score": 4.5,
                    "cwe_id": "CWE-1275",
                    "owasp_category": "A01:2025 - Broken Access Control",
                    "description": f"Cookie '{name}' specifies 'SameSite=None' without the required 'Secure' flag.",
                    "impact": "Modern browsers reject SameSite=None cookies without Secure, breaking intended session state or allowing cross-site leakage.",
                    "remediation": "Always pair 'SameSite=None' with the 'Secure' attribute.",
                    "evidence": f"Raw Set-Cookie header: {header_val}",
                    "affected_url": url,
                    "confidence": "confirmed",
                    "status": "open"
                })

    return findings
