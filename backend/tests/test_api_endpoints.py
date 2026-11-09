"""
SecureAudit Pro - Comprehensive API Integration Test Suite
Validates all REST API endpoints for authentication, target assets, security scans,
vulnerability catalog, reports, attack monitoring radar, and administration.
"""

import uuid
import pytest
from bson import ObjectId
from rest_framework.test import APIClient
from rest_framework import status

from core.database import (
    get_db, USERS, WEBSITES, SCAN_JOBS, VULNERABILITIES,
    MONITOR_TARGETS, THREAT_EVENTS, ORGANIZATIONS
)
from core.authentication import hash_password, create_jwt_tokens


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def auth_user():
    """Seeds an ephemeral test security analyst user and deletes it upon test completion."""
    db = get_db()
    user_email = f"test_analyst_{uuid.uuid4().hex[:8]}@secureaudit.pro"
    user_doc = {
        "email": user_email,
        "password_hash": hash_password("AnalystTestPass2026!"),
        "first_name": "Test",
        "last_name": "Analyst",
        "role": "security_analyst",
        "organization_id": "test_org_id",
        "is_active": True,
        "totp_enabled": False
    }
    res = db[USERS].insert_one(user_doc)
    user_doc["_id"] = res.inserted_id

    tokens = create_jwt_tokens(user_doc)
    try:
        yield user_doc, tokens["access"]
    finally:
        db[USERS].delete_one({"_id": res.inserted_id})


# =========================================================================
# 1. System Health API
# =========================================================================

def test_health_check_api(api_client):
    response = api_client.get("/api/health/")
    assert response.status_code == status.HTTP_200_OK
    assert response.data["status"] == "healthy"
    assert "SecureAudit Pro" in response.data["service"]


# =========================================================================
# 2. Authentication & Profile API
# =========================================================================

def test_auth_register_and_login_flow(api_client):
    db = get_db()
    unique_email = f"test_{uuid.uuid4().hex[:8]}@secureaudit.pro"
    org_name = f"CI/CD Corp {uuid.uuid4().hex[:6]}"
    reg_payload = {
        "email": unique_email,
        "password": "PipelineSecurePass123!",
        "first_name": "Pipeline",
        "last_name": "Tester",
        "organization_name": org_name
    }

    try:
        # 1. Register
        reg_res = api_client.post("/api/auth/register/", data=reg_payload, format="json")
        assert reg_res.status_code == status.HTTP_201_CREATED
        assert "tokens" in reg_res.data
        assert reg_res.data["user"]["email"] == unique_email

        # 2. Login with valid credentials
        login_res = api_client.post("/api/auth/login/", data={
            "email": unique_email,
            "password": "PipelineSecurePass123!"
        }, format="json")
        assert login_res.status_code == status.HTTP_200_OK
        token = login_res.data["tokens"]["access"]
        assert token is not None

        # 3. Login with invalid password
        bad_login = api_client.post("/api/auth/login/", data={
            "email": unique_email,
            "password": "WrongPassword!"
        }, format="json")
        assert bad_login.status_code == status.HTTP_401_UNAUTHORIZED

        # 4. Fetch authenticated user profile
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        profile_res = api_client.get("/api/auth/profile/")
        assert profile_res.status_code == status.HTTP_200_OK
        assert profile_res.data["email"] == unique_email
    finally:
        # Automatically clean up / delete test email ID and test organization from database
        db[USERS].delete_one({"email": unique_email})
        db[ORGANIZATIONS].delete_one({"name": org_name})

    # Assert test email is verified deleted from database
    assert db[USERS].find_one({"email": unique_email}) is None


# =========================================================================
# 3. Target Websites & Verification API
# =========================================================================

def test_websites_api_lifecycle(api_client, auth_user):
    user, token = auth_user
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    # Create website
    payload = {
        "url": "https://audit-target.internal",
        "name": "Audit Target Asset",
        "domain": "audit-target.internal"
    }
    create_res = api_client.post("/api/websites/", data=payload, format="json")
    assert create_res.status_code == status.HTTP_201_CREATED
    website_id = create_res.data["id"]

    # List websites
    list_res = api_client.get("/api/websites/")
    assert list_res.status_code == status.HTTP_200_OK
    assert len(list_res.data) >= 1

    # Get single website
    get_res = api_client.get(f"/api/websites/{website_id}/")
    assert get_res.status_code == status.HTTP_200_OK
    assert get_res.data["name"] == "Audit Target Asset"

    # Verify Challenge API (accepts dns | http | manual_admin)
    verify_res = api_client.post(f"/api/websites/{website_id}/verify/", data={"method": "dns"}, format="json")
    assert verify_res.status_code in (status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST)
    assert "message" in verify_res.data or "error" in verify_res.data


# =========================================================================
# 4. Security Scans Lifecycle API
# =========================================================================

def test_scans_api_lifecycle(api_client, auth_user):
    user, token = auth_user
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    db = get_db()

    # Create a verified website first for foreign relation
    site_res = db[WEBSITES].insert_one({
        "url": "https://scan-test.com",
        "domain": "scan-test.com",
        "name": "Scan Target",
        "verification_status": "verified",
        "organization_id": str(user.get("organization_id", "test_org_id"))
    })
    site_id = str(site_res.inserted_id)

    # Launch new security scan
    scan_payload = {
        "target_url": "https://scan-test.com",
        "website_id": site_id,
        "profile": "standard"
    }
    launch_res = api_client.post("/api/scans/", data=scan_payload, format="json")
    assert launch_res.status_code == status.HTTP_201_CREATED
    scan_id = launch_res.data["id"]
    assert launch_res.data["target_url"] == "https://scan-test.com"

    # List scans
    list_res = api_client.get("/api/scans/")
    assert list_res.status_code == status.HTTP_200_OK
    assert any(s["id"] == scan_id for s in list_res.data)

    # Inspect scan details
    detail_res = api_client.get(f"/api/scans/{scan_id}/")
    assert detail_res.status_code == status.HTTP_200_OK
    assert "status" in detail_res.data

    # Fetch scan events
    events_res = api_client.get(f"/api/scans/{scan_id}/events/")
    assert events_res.status_code == status.HTTP_200_OK

    # Stop scan
    stop_res = api_client.post(f"/api/scans/{scan_id}/stop/")
    assert stop_res.status_code in (status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST)


# =========================================================================
# 5. Vulnerability Catalog & Remediation API
# =========================================================================

def test_vulnerabilities_api(api_client, auth_user):
    user, token = auth_user
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    db = get_db()

    # Seed a test vulnerability with matching organization scope
    vuln_doc = {
        "title": "Cross-Site Scripting (Reflected)",
        "severity": "high",
        "cvss_score": 7.5,
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2025 - Injection",
        "affected_url": "https://example.com/search?q=test",
        "status": "open",
        "organization_id": str(user.get("organization_id", "test_org_id")),
        "comments": [],
        "fix_command": "Use DOMPurify.sanitize(input)",
        "dedup_key": f"test_dedup_{uuid.uuid4().hex}"
    }
    res = db[VULNERABILITIES].insert_one(vuln_doc)
    vuln_id = str(res.inserted_id)

    # List vulnerabilities
    list_res = api_client.get("/api/vulnerabilities/")
    assert list_res.status_code == status.HTTP_200_OK
    assert any(v["id"] == vuln_id for v in list_res.data)

    # Filter by severity
    filter_res = api_client.get("/api/vulnerabilities/?severity=high")
    assert filter_res.status_code == status.HTTP_200_OK

    # Add analyst comment
    comment_res = api_client.post(f"/api/vulnerabilities/{vuln_id}/comments/", data={
        "comment": "Reproduced and confirmed vulnerability in staging environment."
    }, format="json")
    assert comment_res.status_code == status.HTTP_201_CREATED

    # Request Retest
    retest_res = api_client.post(f"/api/vulnerabilities/{vuln_id}/retest/")
    assert retest_res.status_code == status.HTTP_200_OK


# =========================================================================
# 6. Live Threat & Attack Surface Monitoring API
# =========================================================================

def test_monitoring_attack_radar_api(api_client, auth_user):
    user, token = auth_user
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    # 1. Add target to continuous monitoring (IPv4 format)
    target_payload = {
        "target": "140.245.14.175",
        "name": "CI/CD Monitored Asset",
        "interval_minutes": 5
    }
    create_res = api_client.post("/api/monitoring/", data=target_payload, format="json")
    assert create_res.status_code in (status.HTTP_201_CREATED, status.HTTP_400_BAD_REQUEST)

    # 2. List monitored targets
    list_res = api_client.get("/api/monitoring/")
    assert list_res.status_code == status.HTTP_200_OK
    assert "targets" in list_res.data
    assert "summary" in list_res.data

    if create_res.status_code == status.HTTP_201_CREATED and "id" in create_res.data:
        target_id = create_res.data["id"]
    else:
        target_id = list_res.data["targets"][0]["id"]

    # 3. Trigger immediate on-demand diagnostic
    check_res = api_client.post(f"/api/monitoring/{target_id}/check/")
    assert check_res.status_code == status.HTTP_200_OK
    assert "threat_score" in check_res.data

    # 4. Verify live threat events endpoint (CRITICAL: verifies URL ordering fix!)
    events_res = api_client.get("/api/monitoring/events/?status=active")
    assert events_res.status_code == status.HTTP_200_OK

    # 5. Delete monitored target
    del_res = api_client.delete(f"/api/monitoring/{target_id}/")
    assert del_res.status_code == status.HTTP_200_OK


# =========================================================================
# 7. Administration & SOC Metrics API
# =========================================================================

def test_admin_metrics_and_audit_logs_api(api_client, auth_user):
    user, analyst_token = auth_user
    db = get_db()

    # 1. Analyst token tests
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {analyst_token}")
    dash_res = api_client.get("/api/admin/dashboard/")
    assert dash_res.status_code == status.HTTP_200_OK

    # Non-superadmin cannot access system-health (Strict RBAC test)
    health_forbidden = api_client.get("/api/admin/system-health/")
    assert health_forbidden.status_code == status.HTTP_403_FORBIDDEN

    # 2. Super Admin token tests
    admin_user = db[USERS].find_one({"role": "super_admin"})
    created_admin_id = None
    if not admin_user:
        admin_doc = {
            "email": f"pipeline_admin_{uuid.uuid4().hex[:8]}@secureaudit.pro",
            "password_hash": hash_password("AdminPass2026!"),
            "role": "super_admin",
            "is_active": True
        }
        res = db[USERS].insert_one(admin_doc)
        admin_doc["_id"] = res.inserted_id
        admin_user = admin_doc
        created_admin_id = res.inserted_id

    try:
        admin_tokens = create_jwt_tokens(admin_user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {admin_tokens['access']}")

        health_res = api_client.get("/api/admin/system-health/")
        assert health_res.status_code == status.HTTP_200_OK

        audit_res = api_client.get("/api/admin/audit-logs/")
        assert audit_res.status_code == status.HTTP_200_OK
    finally:
        if created_admin_id:
            db[USERS].delete_one({"_id": created_admin_id})
