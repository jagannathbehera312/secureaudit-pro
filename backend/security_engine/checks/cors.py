"""
SecureAudit Pro - Cross-Origin Resource Sharing (CORS) Assessment Module
Tests for arbitrary origin reflection, wildcards with credentials, and null origin trust.
"""

from typing import List, Dict, Any
import requests


def check_cors_misconfiguration(target_url: str, timeout: float = 5.0) -> List[Dict[str, Any]]:
    findings = []
    test_origin = "https://vulnerability-test-probe.example.org"

    try:
        # Probe 1: Arbitrary Origin Reflection
        headers = {
            "Origin": test_origin,
            "User-Agent": "SecureAudit-Pro-Scanner/1.0"
        }
        resp = requests.options(target_url, headers=headers, timeout=timeout, verify=False)
        acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        if acao == test_origin:
            sev = "high" if acac == "true" else "medium"
            cvss = 8.1 if acac == "true" else 5.3
            findings.append({
                "title": "Insecure CORS Policy: Arbitrary Origin Reflection",
                "vuln_type": "cors_arbitrary_origin_reflected",
                "severity": sev,
                "cvss_score": cvss,
                "cwe_id": "CWE-942",
                "owasp_category": "A01:2025 - Broken Access Control",
                "description": f"The application dynamically reflects the request Origin header into Access-Control-Allow-Origin: {acao}{' with Access-Control-Allow-Credentials: true' if acac == 'true' else ''}.",
                "impact": "Enables malicious third-party websites to make authenticated cross-origin requests and read private user data or sensitive API responses.",
                "remediation": "Replace dynamic reflection with a strict allowlist of explicitly trusted domain origins. Never reflect untrusted origins alongside credentials.",
                "evidence": f"Sent 'Origin: {test_origin}' -> Received 'Access-Control-Allow-Origin: {acao}' and 'Access-Control-Allow-Credentials: {acac}'",
                "affected_url": target_url,
                "confidence": "confirmed",
                "status": "open"
            })
        elif acao == "*" and acac == "true":
            findings.append({
                "title": "Insecure CORS Policy: Wildcard Origin with Credentials",
                "vuln_type": "cors_wildcard_with_credentials",
                "severity": "medium",
                "cvss_score": 6.5,
                "cwe_id": "CWE-942",
                "owasp_category": "A01:2025 - Broken Access Control",
                "description": "Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is true. Modern browsers reject this combination, but it reveals flawed security configuration.",
                "impact": "Indicates invalid CORS trust configuration and misconfigured API security policies.",
                "remediation": "Do not specify '*' when credentials are required. Define exact trusted origins.",
                "evidence": f"Headers: Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                "affected_url": target_url,
                "confidence": "confirmed",
                "status": "open"
            })

        # Probe 2: Null Origin Trust
        null_headers = {
            "Origin": "null",
            "User-Agent": "SecureAudit-Pro-Scanner/1.0"
        }
        null_resp = requests.options(target_url, headers=null_headers, timeout=timeout, verify=False)
        null_acao = null_resp.headers.get("Access-Control-Allow-Origin", "").strip()
        null_acac = null_resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        if null_acao == "null":
            findings.append({
                "title": "Insecure CORS Policy: 'null' Origin Permitted",
                "vuln_type": "cors_null_origin_allowed",
                "severity": "medium",
                "cvss_score": 5.7,
                "cwe_id": "CWE-942",
                "owasp_category": "A01:2025 - Broken Access Control",
                "description": "The application trusts the 'null' origin. Sandboxed iframes, local files, and data: URIs produce a 'null' origin.",
                "impact": "An attacker can host a sandboxed iframe that inherits a 'null' origin to bypass cross-origin restrictions and interact with the target API.",
                "remediation": "Do not include 'null' in Access-Control-Allow-Origin allowlists.",
                "evidence": f"Sent 'Origin: null' -> Received 'Access-Control-Allow-Origin: {null_acao}'",
                "affected_url": target_url,
                "confidence": "confirmed",
                "status": "open"
            })

    except Exception:
        pass

    return findings
