"""
SecureAudit Pro - Remediation Task Tracking API Views
Manages assigned vulnerability fix tickets, remediation deadlines, and status verification.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from bson import ObjectId
from datetime import datetime

from core.database import get_db, REMEDIATION_TASKS, VULNERABILITIES, db_manager
from core.permissions import IsSecurityAnalyst, IsReadOnlyUser, enforce_org_scope
from core.authentication import log_audit_event


class RemediationListCreateView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request):
        db = get_db()
        query = enforce_org_scope(request, {})
        status_filter = request.query_params.get("status")
        if status_filter:
            query["status"] = status_filter.lower()

        tasks = list(db[REMEDIATION_TASKS].find(query).sort("created_at", -1))
        return Response(db_manager.serialize_doc(tasks))

    def post(self, request):
        if not IsSecurityAnalyst().has_permission(request, self):
            return Response({"error": "Read-only users cannot create remediation tasks."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        vuln_id = data.get("vulnerability_id")
        assigned_to = data.get("assigned_to", "").strip()
        due_date = data.get("due_date")
        priority = data.get("priority", "medium").lower()
        notes = data.get("notes", "").strip()

        if not vuln_id:
            return Response({"error": "vulnerability_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        db = get_db()
        vuln = db[VULNERABILITIES].find_one({"_id": ObjectId(vuln_id)})
        if not vuln:
            return Response({"error": "Referenced vulnerability not found."}, status=status.HTTP_404_NOT_FOUND)

        task_doc = {
            "vulnerability_id": str(vuln["_id"]),
            "vuln_title": vuln.get("title"),
            "severity": vuln.get("severity"),
            "website_id": vuln.get("website_id"),
            "organization_id": vuln.get("organization_id", request.user.organization_id),
            "assigned_to": assigned_to or request.user.email,
            "created_by": str(request.user.id),
            "due_date": due_date,
            "priority": priority,
            "notes": notes,
            "status": "in_progress", # in_progress | resolved | verified | closed
            "created_at": datetime.utcnow()
        }

        res = db[REMEDIATION_TASKS].insert_one(task_doc)
        task_doc["id"] = str(res.inserted_id)

        # Update vulnerability status to in_progress
        db[VULNERABILITIES].update_one(
            {"_id": ObjectId(vuln_id)},
            {"$set": {"status": "in_progress", "assigned_to": assigned_to}}
        )

        log_audit_event(request.user.id, "REMEDIATION_TASK_CREATED", {"task_id": str(res.inserted_id), "vuln_id": vuln_id})
        return Response(db_manager.serialize_doc(task_doc), status=status.HTTP_201_CREATED)


class RemediationDetailView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request, pk):
        db = get_db()
        task = db[REMEDIATION_TASKS].find_one({"_id": ObjectId(pk)})
        if not task:
            return Response({"error": "Remediation task not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(db_manager.serialize_doc(task))

    def patch(self, request, pk):
        if not IsSecurityAnalyst().has_permission(request, self):
            return Response({"error": "Unauthorized to update remediation task."}, status=status.HTTP_403_FORBIDDEN)

        db = get_db()
        data = request.data
        updates = {}

        if "status" in data:
            updates["status"] = data["status"]
            if data["status"] in ("resolved", "verified"):
                updates["resolved_at"] = datetime.utcnow()
                # If verified, mark corresponding vulnerability as fixed
                task = db[REMEDIATION_TASKS].find_one({"_id": ObjectId(pk)})
                if task and task.get("vulnerability_id"):
                    db[VULNERABILITIES].update_one(
                        {"_id": ObjectId(task["vulnerability_id"])},
                        {"$set": {"status": "fixed"}}
                    )

        if "notes" in data:
            updates["notes"] = data["notes"]
        if "assigned_to" in data:
            updates["assigned_to"] = data["assigned_to"]
        if "due_date" in data:
            updates["due_date"] = data["due_date"]

        updates["updated_at"] = datetime.utcnow()
        db[REMEDIATION_TASKS].update_one({"_id": ObjectId(pk)}, {"$set": updates})

        log_audit_event(request.user.id, "REMEDIATION_TASK_UPDATED", {"task_id": pk, "updates": updates})
        return Response({"message": "Remediation task updated successfully."})
