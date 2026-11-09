"""
SecureAudit Pro - Website / Target Asset Management & Authorization Verification
Enforces strict domain verification via DNS TXT records or HTTP challenges before scanning.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from bson import ObjectId
from datetime import datetime, timedelta
import urllib.parse

from core.database import get_db, WEBSITES, DOMAIN_AUTH, SCAN_JOBS, VULNERABILITIES, db_manager
from core.permissions import IsSecurityAnalyst, IsReadOnlyUser, enforce_org_scope
from core.security import (
    validate_and_resolve_target, generate_verification_tokens,
    verify_domain_dns_txt, verify_domain_http_challenge
)
from core.authentication import log_audit_event


class WebsiteListCreateView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request):
        db = get_db()
        query = enforce_org_scope(request, {})
        websites = list(db[WEBSITES].find(query).sort("created_at", -1))
        return Response(db_manager.serialize_doc(websites))

    def post(self, request):
        if not IsSecurityAnalyst().has_permission(request, self):
            return Response({"error": "Read-only users cannot add target websites."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        name = data.get("name", "").strip()
        url = data.get("url", "").strip()
        env = data.get("environment", "production").lower()
        criticality = data.get("business_criticality", "medium").lower()
        description = data.get("description", "").strip()
        contact_email = data.get("contact_email", "").strip() or request.user.email
        excluded_paths = data.get("excluded_paths", [])

        if not name or not url:
            return Response({"error": "Website name and URL are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate syntax & resolve target
        valid, resolved_ip, norm_url = validate_and_resolve_target(url)
        if not valid:
            return Response({"error": f"Invalid or restricted target URL: {resolved_ip}"}, status=status.HTTP_400_BAD_REQUEST)

        parsed = urllib.parse.urlparse(norm_url)
        domain = parsed.hostname or url

        db = get_db()
        org_id = request.user.organization_id or "default"

        # Generate domain challenge tokens
        challenge_tokens = generate_verification_tokens(domain)

        website_doc = {
            "name": name,
            "url": norm_url,
            "domain": domain,
            "environment": env,
            "business_criticality": criticality,
            "description": description,
            "contact_email": contact_email,
            "organization_id": org_id,
            "owner_user_id": str(request.user.id),
            "verification_status": "unverified",  # unverified | verified | pending
            "verification_method": None,
            "verification_tokens": challenge_tokens,
            "authorization_evidence": data.get("authorization_evidence", "Self-declaration"),
            "authorization_expiry": datetime.utcnow() + timedelta(days=365),
            "security_score": 100.0,
            "risk_level": "Unassessed",
            "excluded_paths": excluded_paths if isinstance(excluded_paths, list) else [],
            "created_at": datetime.utcnow(),
            "last_scanned_at": None
        }

        res = db[WEBSITES].insert_one(website_doc)
        website_doc["id"] = str(res.inserted_id)

        log_audit_event(
            request.user.id, "WEBSITE_REGISTERED",
            {"website_id": str(res.inserted_id), "domain": domain, "url": norm_url},
            organization_id=org_id
        )

        return Response(db_manager.serialize_doc(website_doc), status=status.HTTP_201_CREATED)


class WebsiteDetailView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request, pk):
        db = get_db()
        try:
            site = db[WEBSITES].find_one({"_id": ObjectId(pk)})
        except Exception:
            site = None

        if not site:
            return Response({"error": "Website not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user.role != "super_admin" and site.get("organization_id") != request.user.organization_id:
            return Response({"error": "Access denied to target website."}, status=status.HTTP_403_FORBIDDEN)

        # Pull recent scans and active vulnerability counts
        scans = list(db[SCAN_JOBS].find({"website_id": str(site["_id"])}).sort("created_at", -1).limit(5))
        vulns = list(db[VULNERABILITIES].find({"website_id": str(site["_id"])}))

        data = db_manager.serialize_doc(site)
        data["recent_scans"] = db_manager.serialize_doc(scans)
        data["total_vulnerabilities"] = len(vulns)
        data["critical_count"] = sum(1 for v in vulns if v.get("severity") == "critical" and v.get("status") != "fixed")
        data["high_count"] = sum(1 for v in vulns if v.get("severity") == "high" and v.get("status") != "fixed")
        data["medium_count"] = sum(1 for v in vulns if v.get("severity") == "medium" and v.get("status") != "fixed")
        data["low_count"] = sum(1 for v in vulns if v.get("severity") == "low" and v.get("status") != "fixed")

        return Response(data)

    def put(self, request, pk):
        if not IsSecurityAnalyst().has_permission(request, self):
            return Response({"error": "Unauthorized to update website."}, status=status.HTTP_403_FORBIDDEN)

        db = get_db()
        data = request.data
        update_fields = {}
        for f in ["name", "description", "environment", "business_criticality", "contact_email", "excluded_paths"]:
            if f in data:
                update_fields[f] = data[f]

        db[WEBSITES].update_one({"_id": ObjectId(pk)}, {"$set": update_fields})
        return Response({"message": "Website updated successfully."})

    def delete(self, request, pk):
        if not IsSecurityAnalyst().has_permission(request, self):
            return Response({"error": "Unauthorized to delete website."}, status=status.HTTP_403_FORBIDDEN)

        db = get_db()
        db[WEBSITES].delete_one({"_id": ObjectId(pk)})
        log_audit_event(request.user.id, "WEBSITE_DELETED", {"website_id": pk})
        return Response({"message": "Website deleted successfully."})


class WebsiteVerifyChallengeView(APIView):
    """Verifies domain ownership via DNS TXT record or HTTP challenge file."""
    permission_classes = [IsSecurityAnalyst]

    def post(self, request, pk):
        db = get_db()
        try:
            site = db[WEBSITES].find_one({"_id": ObjectId(pk)})
        except Exception:
            site = None

        if not site:
            return Response({"error": "Website not found."}, status=status.HTTP_404_NOT_FOUND)

        method = request.data.get("method", "dns").lower() # dns | http | manual_admin
        tokens = site.get("verification_tokens", {})
        domain = site.get("domain")

        if method == "manual_admin":
            if request.user.role not in ("super_admin", "org_admin"):
                return Response({"error": "Only administrators can approve manual authorization evidence."}, status=status.HTTP_403_FORBIDDEN)
            db[WEBSITES].update_one(
                {"_id": ObjectId(pk)},
                {"$set": {
                    "verification_status": "verified",
                    "verification_method": "manual_admin_approval",
                    "verified_at": datetime.utcnow(),
                    "verified_by": str(request.user.id)
                }}
            )
            log_audit_event(request.user.id, "DOMAIN_VERIFIED_MANUAL", {"website_id": pk, "domain": domain})
            return Response({"success": True, "message": "Domain ownership confirmed via administrator authorization declaration."})

        elif method == "dns":
            expected_token = tokens.get("token")
            ok, msg = verify_domain_dns_txt(domain, expected_token)
            if ok:
                db[WEBSITES].update_one(
                    {"_id": ObjectId(pk)},
                    {"$set": {
                        "verification_status": "verified",
                        "verification_method": "dns_txt",
                        "verified_at": datetime.utcnow()
                    }}
                )
                log_audit_event(request.user.id, "DOMAIN_VERIFIED_DNS", {"website_id": pk, "domain": domain})
                return Response({"success": True, "message": msg})
            return Response({"success": False, "error": msg}, status=status.HTTP_400_BAD_REQUEST)

        elif method == "http":
            expected_content = tokens.get("http_challenge_content")
            ok, msg = verify_domain_http_challenge(site.get("url"), expected_content)
            if ok:
                db[WEBSITES].update_one(
                    {"_id": ObjectId(pk)},
                    {"$set": {
                        "verification_status": "verified",
                        "verification_method": "http_challenge",
                        "verified_at": datetime.utcnow()
                    }}
                )
                log_audit_event(request.user.id, "DOMAIN_VERIFIED_HTTP", {"website_id": pk, "domain": domain})
                return Response({"success": True, "message": msg})
            return Response({"success": False, "error": msg}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"error": "Unsupported verification method."}, status=status.HTTP_400_BAD_REQUEST)
