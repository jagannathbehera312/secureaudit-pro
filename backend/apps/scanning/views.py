"""
SecureAudit Pro - Scanning API Views
Handles scan initiation, live stage monitoring, cancellation, retry, and scan comparison.
"""

import urllib.parse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from bson import ObjectId
from datetime import datetime

from core.database import get_db, SCAN_JOBS, SCAN_EVENTS, SCAN_RESULTS, WEBSITES, VULNERABILITIES, db_manager
from core.permissions import IsSecurityAnalyst, IsReadOnlyUser, enforce_org_scope
from core.authentication import log_audit_event
from tasks.scan_tasks import dispatch_scan_async


class ScanListCreateView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request):
        db = get_db()
        query = enforce_org_scope(request, {})
        website_id = request.query_params.get("website_id")
        if website_id:
            query["website_id"] = website_id

        scans = list(db[SCAN_JOBS].find(query).sort("created_at", -1).limit(50))
        return Response(db_manager.serialize_doc(scans))

    def post(self, request):
        if not IsSecurityAnalyst().has_permission(request, self):
            return Response({"error": "Read-only users cannot initiate security scans."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        website_id = data.get("website_id")
        target_url = (data.get("target_url") or data.get("url") or "").strip()
        profile = data.get("profile", "standard") # quick | standard | comprehensive | custom
        options = data.get("options", {})

        db = get_db()

        if not website_id and not target_url:
            return Response({"error": "Either target_url or website_id is required to launch a scan."}, status=status.HTTP_400_BAD_REQUEST)

        site = None
        if website_id:
            try:
                site = db[WEBSITES].find_one({"_id": ObjectId(website_id)})
            except Exception:
                site = None
            if not site and not target_url:
                return Response({"error": "Selected target website not found."}, status=status.HTTP_404_NOT_FOUND)

        # On-Demand Target Registration if URL provided directly
        if not site and target_url:
            if not target_url.startswith(("http://", "https://")):
                target_url = "https://" + target_url

            parsed = urllib.parse.urlparse(target_url)
            hostname = parsed.hostname
            if not hostname:
                return Response({"error": "Invalid target URL: missing hostname."}, status=status.HTTP_400_BAD_REQUEST)

            # Match existing inventory or create dynamically
            site = db[WEBSITES].find_one({
                "organization_id": request.user.organization_id,
                "$or": [{"url": target_url}, {"domain": hostname}]
            })

            if not site:
                site_name = data.get("website_name", "").strip() or f"{hostname}"
                site_doc = {
                    "name": site_name,
                    "url": target_url,
                    "domain": hostname,
                    "environment": data.get("environment", "production"),
                    "business_criticality": data.get("business_criticality", "medium"),
                    "description": data.get("description", f"On-demand security audit target: {target_url}"),
                    "contact_email": request.user.email,
                    "organization_id": request.user.organization_id,
                    "owner_user_id": str(request.user.id),
                    "verification_status": "verified",
                    "verification_method": "on_demand_declaration",
                    "verified_at": datetime.utcnow(),
                    "security_score": 100.0,
                    "risk_level": "Under Assessment",
                    "excluded_paths": options.get("excluded_paths", []),
                    "created_at": datetime.utcnow(),
                    "last_scanned_at": datetime.utcnow()
                }
                res_ins = db[WEBSITES].insert_one(site_doc)
                site_doc["_id"] = res_ins.inserted_id
                site = site_doc

            website_id = str(site["_id"])

        # Safety Check: Target Must Be Verified
        is_verified = site.get("verification_status") == "verified"
        if not is_verified and request.user.role not in ("super_admin", "org_admin"):
            return Response({
                "error": "Target website has not been verified. Complete domain verification before running scans."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Prevent concurrent running scans on the exact same website
        running_scan = db[SCAN_JOBS].find_one({"website_id": str(site["_id"]), "status": "running"})
        if running_scan:
            return Response({
                "error": f"A scan is already in progress for this website (Scan ID: {str(running_scan['_id'])}). Please wait for it to complete or stop it before launching a new one."
            }, status=status.HTTP_400_BAD_REQUEST)

        scan_doc = {
            "website_id": str(site["_id"]),
            "website_name": site.get("name"),
            "target_url": site.get("url"),
            "domain": site.get("domain"),
            "profile": profile,
            "options": options,
            "status": "pending",
            "progress": 0,
            "current_stage": "Queued",
            "findings_count": 0,
            "security_score": None,
            "initiated_by": str(request.user.id),
            "organization_id": site.get("organization_id", request.user.organization_id),
            "created_at": datetime.utcnow(),
            "started_at": None,
            "completed_at": None
        }

        res = db[SCAN_JOBS].insert_one(scan_doc)
        scan_id = str(res.inserted_id)
        scan_doc["id"] = scan_id

        log_audit_event(
            request.user.id, "SCAN_INITIATED",
            {"scan_id": scan_id, "website_id": website_id, "profile": profile},
            organization_id=scan_doc["organization_id"]
        )

        # Dispatch background task asynchronously
        dispatch_scan_async(scan_id)

        return Response(db_manager.serialize_doc(scan_doc), status=status.HTTP_201_CREATED)


class ScanDetailView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request, pk):
        db = get_db()
        try:
            job = db[SCAN_JOBS].find_one({"_id": ObjectId(pk)})
        except Exception:
            job = None

        if not job:
            return Response({"error": "Scan job not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response(db_manager.serialize_doc(job))


class ScanStopView(APIView):
    permission_classes = [IsSecurityAnalyst]

    def post(self, request, pk):
        db = get_db()
        job = db[SCAN_JOBS].find_one({"_id": ObjectId(pk)})
        if not job:
            return Response({"error": "Scan job not found."}, status=status.HTTP_404_NOT_FOUND)

        if job.get("status") not in ("pending", "running"):
            return Response({"error": f"Cannot stop scan in state: {job.get('status')}"}, status=status.HTTP_400_BAD_REQUEST)

        db[SCAN_JOBS].update_one(
            {"_id": ObjectId(pk)},
            {"$set": {"status": "cancelled", "completed_at": datetime.utcnow()}}
        )
        log_audit_event(request.user.id, "SCAN_CANCELLED", {"scan_id": pk})
        return Response({"message": "Scan execution cancelled successfully."})


class ScanRetryView(APIView):
    permission_classes = [IsSecurityAnalyst]

    def post(self, request, pk):
        db = get_db()
        job = db[SCAN_JOBS].find_one({"_id": ObjectId(pk)})
        if not job:
            return Response({"error": "Original scan not found."}, status=status.HTTP_404_NOT_FOUND)

        new_scan = {
            "website_id": job.get("website_id"),
            "website_name": job.get("website_name"),
            "target_url": job.get("target_url"),
            "domain": job.get("domain"),
            "profile": job.get("profile", "standard"),
            "options": job.get("options", {}),
            "status": "pending",
            "progress": 0,
            "current_stage": "Queued",
            "findings_count": 0,
            "security_score": None,
            "initiated_by": str(request.user.id),
            "organization_id": job.get("organization_id"),
            "created_at": datetime.utcnow()
        }
        res = db[SCAN_JOBS].insert_one(new_scan)
        scan_id = str(res.inserted_id)
        new_scan["id"] = scan_id

        log_audit_event(request.user.id, "SCAN_RETRIED", {"old_scan_id": pk, "new_scan_id": scan_id})
        dispatch_scan_async(scan_id)

        return Response(db_manager.serialize_doc(new_scan), status=status.HTTP_201_CREATED)


class ScanEventsView(APIView):
    """Returns live stage events for the scan monitoring timeline."""
    permission_classes = [IsReadOnlyUser]

    def get(self, request, pk):
        db = get_db()
        events = list(db[SCAN_EVENTS].find({"scan_id": pk}).sort("timestamp", 1))
        job = db[SCAN_JOBS].find_one({"_id": ObjectId(pk)}, {"status": 1, "progress": 1, "current_stage": 1})
        return Response({
            "status": job.get("status") if job else "unknown",
            "progress": job.get("progress", 0) if job else 0,
            "current_stage": job.get("current_stage", "") if job else "",
            "events": db_manager.serialize_doc(events)
        })


class ScanResultsView(APIView):
    """Retrieves full scan result summary including findings, tech stack, and SSL info."""
    permission_classes = [IsReadOnlyUser]

    def get(self, request, pk):
        db = get_db()
        result = db[SCAN_RESULTS].find_one({"scan_id": pk})
        if not result:
            # Fallback to scan_jobs summary if results haven't finalized
            job = db[SCAN_JOBS].find_one({"_id": ObjectId(pk)})
            if not job:
                return Response({"error": "Scan results not found."}, status=status.HTTP_404_NOT_FOUND)
            return Response(db_manager.serialize_doc(job))

        vulns = list(db[VULNERABILITIES].find({"last_scan_id": pk}))
        data = db_manager.serialize_doc(result)
        data["vulnerabilities"] = db_manager.serialize_doc(vulns)
        return Response(data)


class ScanCompareView(APIView):
    """
    Compares two scans side-by-side to track:
    - New findings discovered
    - Resolved findings fixed between scans
    - Persistent findings
    - Security score improvement / delta
    """
    permission_classes = [IsReadOnlyUser]

    def post(self, request):
        scan_id_a = request.data.get("scan_id_a")
        scan_id_b = request.data.get("scan_id_b")

        if not scan_id_a or not scan_id_b:
            return Response({"error": "scan_id_a and scan_id_b are required."}, status=status.HTTP_400_BAD_REQUEST)

        db = get_db()
        job_a = db[SCAN_JOBS].find_one({"_id": ObjectId(scan_id_a)})
        job_b = db[SCAN_JOBS].find_one({"_id": ObjectId(scan_id_b)})

        if not job_a or not job_b:
            return Response({"error": "One or both scans could not be found."}, status=status.HTTP_404_NOT_FOUND)

        # Pull vulnerabilities linked to each scan
        res_a = db[SCAN_RESULTS].find_one({"scan_id": scan_id_a}) or {}
        res_b = db[SCAN_RESULTS].find_one({"scan_id": scan_id_b}) or {}

        vulns_a = list(db[VULNERABILITIES].find({"last_scan_id": scan_id_a}))
        vulns_b = list(db[VULNERABILITIES].find({"last_scan_id": scan_id_b}))

        keys_a = {v.get("dedup_key"): v for v in vulns_a if v.get("dedup_key")}
        keys_b = {v.get("dedup_key"): v for v in vulns_b if v.get("dedup_key")}

        # Scan B is newer than Scan A
        new_findings = [v for k, v in keys_b.items() if k not in keys_a]
        resolved_findings = [v for k, v in keys_a.items() if k not in keys_b]
        persistent_findings = [v for k, v in keys_b.items() if k in keys_a]

        score_a = job_a.get("security_score", 0.0) or 0.0
        score_b = job_b.get("security_score", 0.0) or 0.0
        score_delta = round(score_b - score_a, 1)

        return Response({
            "scan_a": db_manager.serialize_doc(job_a),
            "scan_b": db_manager.serialize_doc(job_b),
            "score_a": score_a,
            "score_b": score_b,
            "score_delta": score_delta,
            "improved": score_delta > 0,
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "persistent_count": len(persistent_findings),
            "new_findings": db_manager.serialize_doc(new_findings),
            "resolved_findings": db_manager.serialize_doc(resolved_findings),
            "persistent_findings": db_manager.serialize_doc(persistent_findings)
        })
