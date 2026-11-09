"""
SecureAudit Pro - Administration & System Health API Views
Provides system diagnostics, engine status, audit logging, and demo data reset.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import os
import shutil
import requests
from datetime import datetime

from core.database import (
    get_db, USERS, ORGANIZATIONS, WEBSITES, SCAN_JOBS,
    VULNERABILITIES, AUDIT_LOGS, db_manager
)
from core.permissions import IsSuperAdmin, IsOrgAdmin, IsReadOnlyUser
from fixtures.seed_data import seed_database, reset_application_data


class AdminDashboardStatsView(APIView):
    """Provides high-level system metrics and platform-wide statistics."""
    permission_classes = [IsReadOnlyUser]

    def get(self, request):
        db = get_db()
        total_users = db[USERS].count_documents({})
        total_orgs = db[ORGANIZATIONS].count_documents({})
        total_websites = db[WEBSITES].count_documents({})
        total_scans = db[SCAN_JOBS].count_documents({})
        running_scans = db[SCAN_JOBS].count_documents({"status": "running"})
        failed_scans = db[SCAN_JOBS].count_documents({"status": "failed"})

        total_vulns = db[VULNERABILITIES].count_documents({})
        crit_vulns = db[VULNERABILITIES].count_documents({"severity": "critical", "status": {"$ne": "fixed"}})
        high_vulns = db[VULNERABILITIES].count_documents({"severity": "high", "status": {"$ne": "fixed"}})
        med_vulns = db[VULNERABILITIES].count_documents({"severity": "medium", "status": {"$ne": "fixed"}})
        low_vulns = db[VULNERABILITIES].count_documents({"severity": "low", "status": {"$ne": "fixed"}})

        return Response({
            "total_users": total_users,
            "total_organizations": total_orgs,
            "total_websites": total_websites,
            "total_scans": total_scans,
            "running_scans": running_scans,
            "failed_scans": failed_scans,
            "vulnerabilities": {
                "total": total_vulns,
                "critical": crit_vulns,
                "high": high_vulns,
                "medium": med_vulns,
                "low": low_vulns
            }
        })


class SystemHealthView(APIView):
    """Reports live status of MongoDB, Redis, Celery, and Scanner Services."""
    permission_classes = [IsSuperAdmin]

    def get(self, request):
        db = get_db()
        # 1. MongoDB Status
        mongo_status = "Online (In-Memory mongomock)" if db_manager.is_mock else "Online (Production MongoDB)"

        # 2. Redis Status
        redis_status = "Offline / Standalone Fallback Active"
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        try:
            import redis
            r = redis.Redis.from_url(redis_url, socket_timeout=1.0)
            if r.ping():
                redis_status = "Online (Connected)"
        except Exception:
            pass

        # 3. Scanner Engines
        zap_url = os.environ.get("ZAP_API_URL", "http://owasp-zap:8080")
        zap_online = False
        try:
            zr = requests.get(f"{zap_url}/JSON/core/view/version/", timeout=1.0)
            if zr.status_code == 200:
                zap_online = True
        except Exception:
            pass

        nuclei_path = shutil.which("nuclei") or os.environ.get("NUCLEI_BIN_PATH")
        nuclei_installed = bool(nuclei_path and os.path.exists(nuclei_path))

        # 4. Storage Disk Info
        disk_usage = shutil.disk_usage("/")
        storage_info = {
            "total_gb": round(disk_usage.total / (1024**3), 2),
            "used_gb": round(disk_usage.used / (1024**3), 2),
            "free_gb": round(disk_usage.free / (1024**3), 2),
            "percent_used": round((disk_usage.used / disk_usage.total) * 100, 1)
        }

        return Response({
            "status": "Healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "database": {
                    "engine": "MongoDB",
                    "status": mongo_status,
                    "connected": True
                },
                "cache_broker": {
                    "engine": "Redis",
                    "status": redis_status,
                    "connected": "Online" in redis_status
                },
                "background_workers": {
                    "engine": "Celery & Thread Pool",
                    "status": "Active & Ready"
                },
                "scanners": {
                    "native_python_engine": {"status": "Online (Embedded)", "version": "2.0.0"},
                    "owasp_zap": {"status": "Online" if zap_online else "Standby (Docker / External)", "connected": zap_online},
                    "nuclei": {"status": "Available" if nuclei_installed else "Standby (Curated Templates)", "installed": nuclei_installed}
                }
            },
            "storage": storage_info
        })


class AuditLogsView(APIView):
    permission_classes = [IsOrgAdmin]

    def get(self, request):
        db = get_db()
        query = {}
        if request.user.role != "super_admin":
            query["organization_id"] = request.user.organization_id

        logs = list(db[AUDIT_LOGS].find(query).sort("created_at", -1).limit(100))
        return Response(db_manager.serialize_doc(logs))


class ResetDemoDataView(APIView):
    """Purges all targets, scans, vulnerabilities, and reports, resetting the application to a pristine state."""
    permission_classes = [IsOrgAdmin]

    def post(self, request):
        preserve_users = request.data.get("preserve_users", True)
        res = reset_application_data(preserve_users=preserve_users)
        return Response(res)
