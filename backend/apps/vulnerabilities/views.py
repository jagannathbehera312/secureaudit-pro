"""
SecureAudit Pro - Vulnerability Management API Views
Provides querying, filtering, status workflows, comments, and retest requests.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from bson import ObjectId
from datetime import datetime
import re

from core.database import get_db, VULNERABILITIES, REMEDIATION_TASKS, db_manager
from core.permissions import IsSecurityAnalyst, IsReadOnlyUser, enforce_org_scope
from core.authentication import log_audit_event


class VulnerabilityListView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request):
        db = get_db()
        query = enforce_org_scope(request, {})

        # Filters
        severity = request.query_params.get("severity")
        if severity:
            query["severity"] = severity.lower()

        status_param = request.query_params.get("status")
        if status_param:
            query["status"] = status_param.lower()

        owasp = request.query_params.get("owasp_category")
        if owasp:
            query["owasp_category"] = {"$regex": owasp, "$options": "i"}

        website_id = request.query_params.get("website_id")
        if website_id:
            query["website_id"] = website_id

        scan_id = request.query_params.get("scan_id")
        if scan_id:
            query["$or"] = [{"scan_id": scan_id}, {"last_scan_id": scan_id}]

        search = request.query_params.get("search")
        if search:
            query["$or"] = [
                {"title": {"$regex": re.escape(search), "$options": "i"}},
                {"affected_url": {"$regex": re.escape(search), "$options": "i"}},
                {"cwe_id": {"$regex": re.escape(search), "$options": "i"}}
            ]

        vulns = list(db[VULNERABILITIES].find(query).sort("created_at", -1).limit(100))
        return Response(db_manager.serialize_doc(vulns))


class VulnerabilityDetailView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request, pk):
        db = get_db()
        try:
            vuln = db[VULNERABILITIES].find_one({"_id": ObjectId(pk)})
        except Exception:
            vuln = None

        if not vuln:
            return Response({"error": "Vulnerability not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response(db_manager.serialize_doc(vuln))

    def patch(self, request, pk):
        if not IsSecurityAnalyst().has_permission(request, self):
            return Response({"error": "Unauthorized to update vulnerability."}, status=status.HTTP_403_FORBIDDEN)

        db = get_db()
        data = request.data
        update_fields = {}

        if "status" in data:
            valid_statuses = ("open", "confirmed", "in_progress", "fixed", "accepted_risk", "false_positive", "reopened")
            new_status = data["status"].lower()
            if new_status not in valid_statuses:
                return Response({"error": f"Invalid status: {new_status}"}, status=status.HTTP_400_BAD_REQUEST)
            update_fields["status"] = new_status

        if "assigned_to" in data:
            update_fields["assigned_to"] = data["assigned_to"]

        if not update_fields:
            return Response({"message": "No valid fields to update."})

        update_fields["updated_at"] = datetime.utcnow()
        db[VULNERABILITIES].update_one({"_id": ObjectId(pk)}, {"$set": update_fields})
        log_audit_event(request.user.id, "VULN_UPDATED", {"vuln_id": pk, "updates": update_fields})

        return Response({"message": "Vulnerability updated successfully."})


class VulnerabilityCommentView(APIView):
    permission_classes = [IsSecurityAnalyst]

    def post(self, request, pk):
        comment_text = request.data.get("comment", "").strip()
        if not comment_text:
            return Response({"error": "Comment text cannot be empty."}, status=status.HTTP_400_BAD_REQUEST)

        db = get_db()
        new_comment = {
            "id": str(ObjectId()),
            "user_id": str(request.user.id),
            "user_name": request.user.full_name,
            "comment": comment_text,
            "created_at": datetime.utcnow().isoformat()
        }

        db[VULNERABILITIES].update_one(
            {"_id": ObjectId(pk)},
            {"$push": {"comments": new_comment}}
        )

        log_audit_event(request.user.id, "VULN_COMMENT_ADDED", {"vuln_id": pk})
        return Response({"message": "Comment posted successfully.", "comment": new_comment}, status=status.HTTP_201_CREATED)


class VulnerabilityRetestView(APIView):
    """Requests a retest of a specific vulnerability after remediation."""
    permission_classes = [IsSecurityAnalyst]

    def post(self, request, pk):
        db = get_db()
        vuln = db[VULNERABILITIES].find_one({"_id": ObjectId(pk)})
        if not vuln:
            return Response({"error": "Vulnerability not found."}, status=status.HTTP_404_NOT_FOUND)

        db[VULNERABILITIES].update_one(
            {"_id": ObjectId(pk)},
            {"$set": {
                "status": "in_progress",
                "retest_requested": True,
                "retest_requested_at": datetime.utcnow(),
                "retest_requested_by": str(request.user.id)
            }}
        )
        log_audit_event(request.user.id, "VULN_RETEST_REQUESTED", {"vuln_id": pk})
        return Response({"message": f"Retest requested for '{vuln.get('title')}'. Status set to in_progress."})
