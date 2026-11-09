"""
SecureAudit Pro - Initial Organization & User Account Seeder
Populates initial organizations and role-based user accounts.
Does NOT populate mock websites, scans, or vulnerabilities, leaving the platform
clean and ready for on-demand user-specified target scans.
"""

from datetime import datetime, timedelta
from core.database import (
    get_db, USERS, ORGANIZATIONS, WEBSITES, DOMAIN_AUTH, SCAN_JOBS,
    SCAN_EVENTS, SCAN_RESULTS, VULNERABILITIES, VULN_EVIDENCE,
    REMEDIATION_TASKS, REPORTS, NOTIFICATIONS, AUDIT_LOGS
)
from core.authentication import hash_password


def seed_database(reset_existing: bool = False):
    """
    Ensures the default organization and the 4 core role-based user accounts exist.
    Leaves target websites, scans, and vulnerabilities completely clean (empty).
    """
    db = get_db()

    if reset_existing:
        db[USERS].delete_many({})
        db[ORGANIZATIONS].delete_many({})
        db[WEBSITES].delete_many({})
        db[DOMAIN_AUTH].delete_many({})
        db[SCAN_JOBS].delete_many({})
        db[SCAN_EVENTS].delete_many({})
        db[SCAN_RESULTS].delete_many({})
        db[VULNERABILITIES].delete_many({})
        db[VULN_EVIDENCE].delete_many({})
        db[REMEDIATION_TASKS].delete_many({})
        db[REPORTS].delete_many({})
        db[NOTIFICATIONS].delete_many({})
        db[AUDIT_LOGS].delete_many({})

    # 1. Organization Check / Creation
    org = db[ORGANIZATIONS].find_one({"name": "Apex Global Financial & Cloud"})
    if not org:
        org_res = db[ORGANIZATIONS].insert_one({
            "name": "Apex Global Financial & Cloud",
            "description": "Enterprise Security Audit & Penetration Testing Operations",
            "created_at": datetime.utcnow() - timedelta(days=60)
        })
        org_id = str(org_res.inserted_id)
    else:
        org_id = str(org["_id"])

    # 2. Users (SuperAdmin, OrgAdmin, SecurityAnalyst, Auditor)
    users_data = [
        {
            "email": "admin@secureaudit.pro",
            "password_hash": hash_password("Admin@SecureAudit2026!"),
            "first_name": "Eleanor",
            "last_name": "Vance",
            "role": "super_admin",
            "organization_id": org_id,
            "is_active": True,
            "totp_enabled": False,
            "created_at": datetime.utcnow() - timedelta(days=60)
        },
        {
            "email": "orgadmin@secureaudit.pro",
            "password_hash": hash_password("OrgAdmin@SecureAudit2026!"),
            "first_name": "Marcus",
            "last_name": "Brody",
            "role": "org_admin",
            "organization_id": org_id,
            "is_active": True,
            "totp_enabled": False,
            "created_at": datetime.utcnow() - timedelta(days=50)
        },
        {
            "email": "analyst@secureaudit.pro",
            "password_hash": hash_password("Analyst@SecureAudit2026!"),
            "first_name": "Sophia",
            "last_name": "Chen",
            "role": "security_analyst",
            "organization_id": org_id,
            "is_active": True,
            "totp_enabled": False,
            "created_at": datetime.utcnow() - timedelta(days=45)
        },
        {
            "email": "auditor@secureaudit.pro",
            "password_hash": hash_password("Auditor@SecureAudit2026!"),
            "first_name": "Julian",
            "last_name": "Ross",
            "role": "read_only",
            "organization_id": org_id,
            "is_active": True,
            "totp_enabled": False,
            "created_at": datetime.utcnow() - timedelta(days=30)
        }
    ]

    for u in users_data:
        if not db[USERS].find_one({"email": u["email"]}):
            db[USERS].insert_one(u)

    return True


def reset_application_data(preserve_users: bool = True):
    """
    Completely purges all registered websites, scan jobs, scan events, scan results,
    vulnerabilities, evidence records, remediation tasks, generated reports, and notifications.
    Preserves core login users and organization so the app remains accessible in a clean state.
    """
    db = get_db()
    
    # Delete all operational & assessment data
    db[WEBSITES].delete_many({})
    db[DOMAIN_AUTH].delete_many({})
    db[SCAN_JOBS].delete_many({})
    db[SCAN_EVENTS].delete_many({})
    db[SCAN_RESULTS].delete_many({})
    db[VULNERABILITIES].delete_many({})
    db[VULN_EVIDENCE].delete_many({})
    db[REMEDIATION_TASKS].delete_many({})
    db[REPORTS].delete_many({})
    db[NOTIFICATIONS].delete_many({})
    db[AUDIT_LOGS].delete_many({})

    if not preserve_users:
        db[USERS].delete_many({})
        db[ORGANIZATIONS].delete_many({})

    # Ensure users and org are initialized
    seed_database(reset_existing=False)

    return {
        "status": "success",
        "message": "All registered targets, scans, vulnerabilities, and reports successfully wiped. Application is reset to a clean state."
    }
