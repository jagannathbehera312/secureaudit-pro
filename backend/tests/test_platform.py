"""
SecureAudit Pro - Comprehensive Unit & Integration Test Suite
Validates authentication, SSRF protection, scoring algorithms, and report generation.
"""

import pytest
from core.database import get_db, USERS, WEBSITES, SCAN_JOBS, VULNERABILITIES
from core.authentication import (
    hash_password, verify_password, create_jwt_tokens, decode_jwt_token,
    generate_totp_secret, verify_totp_token, get_totp_token
)
from core.security import (
    validate_and_resolve_target, compute_vulnerability_dedup_key
)
from core.scoring import calculate_security_score
from security_engine.dispatcher import ScanDispatcher
from apps.reports.views import render_html_report


def test_password_hashing():
    pw = "SuperSecurePassword123!"
    hashed = hash_password(pw)
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_tokens():
    mock_user = {
        "_id": "65b938f2a1b2c3d4e5f60718",
        "email": "test@secureaudit.pro",
        "role": "security_analyst",
        "organization_id": "org_123"
    }
    tokens = create_jwt_tokens(mock_user)
    assert "access" in tokens
    assert "refresh" in tokens

    payload = decode_jwt_token(tokens["access"])
    assert payload["email"] == "test@secureaudit.pro"
    assert payload["role"] == "security_analyst"


def test_totp_generation_and_verification():
    secret = generate_totp_secret()
    assert len(secret) == 32
    token = get_totp_token(secret)
    assert len(token) == 6
    assert verify_totp_token(secret, token) is True
    assert verify_totp_token(secret, "000000") is False


def test_ssrf_protection_blocks_private_and_cloud_ips():
    # Loopback
    valid, msg, _ = validate_and_resolve_target("http://127.0.0.1:8080/admin")
    assert valid is False
    assert "SSRF" in msg or "restricted" in msg or "blocked" in msg

    # AWS Cloud metadata
    valid, msg, _ = validate_and_resolve_target("http://169.254.169.254/latest/meta-data/")
    assert valid is False
    assert "SSRF" in msg or "restricted" in msg or "blocked" in msg

    # RFC 1918 Private range
    valid, msg, _ = validate_and_resolve_target("http://192.168.1.1/router")
    assert valid is False


def test_vulnerability_dedup_key():
    key1 = compute_vulnerability_dedup_key("example.com", "missing_csp", "/login", "")
    key2 = compute_vulnerability_dedup_key("example.com", "missing_csp", "/login", "")
    key3 = compute_vulnerability_dedup_key("example.com", "missing_csp", "/dashboard", "")
    assert key1 == key2
    assert key1 != key3


def test_security_scoring_formula():
    # Zero vulnerabilities
    score_clean = calculate_security_score([])
    assert score_clean["score"] == 100.0

    # With critical and high vulnerabilities
    mock_vulns = [
        {"severity": "critical", "confidence": "confirmed", "status": "open", "owasp_category": "A01:2025 - Broken Access Control"},
        {"severity": "high", "confidence": "confirmed", "status": "open", "owasp_category": "A02:2025 - Security Misconfiguration"}
    ]
    score_dirty = calculate_security_score(mock_vulns, business_criticality="critical")
    assert score_dirty["score"] < 70.0
    assert score_dirty["severity_counts"]["critical"] == 1
    assert score_dirty["severity_counts"]["high"] == 1


def test_html_report_rendering():
    job = {
        "_id": "65b938f2a1b2c3d4e5f60719",
        "target_url": "https://example.com",
        "domain": "example.com",
        "profile": "comprehensive",
        "security_score": 85.0,
        "risk_level": "Moderate Risk"
    }
    website = {"url": "https://example.com", "domain": "example.com"}
    result = {"severity_counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0}}
    vulns = [
        {
            "title": "Missing HSTS Header",
            "severity": "medium",
            "cvss_score": 5.3,
            "cwe_id": "CWE-319",
            "owasp_category": "A04:2025 - Cryptographic Failures",
            "affected_url": "https://example.com/",
            "description": "HSTS is absent.",
            "impact": "MITM risk.",
            "remediation": "Add Strict-Transport-Security."
        }
    ]
    html = render_html_report(job, website, result, vulns)
    assert "SECUREAUDIT PRO" in html
    assert "example.com" in html
    assert "Missing HSTS Header" in html
    assert "85.0/100" in html
