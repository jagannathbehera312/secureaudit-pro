"""
SecureAudit Pro - Organizations API Views
Manages multi-tenant organizations, invitations, and member access.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from bson import ObjectId
from datetime import datetime

from core.database import get_db, ORGANIZATIONS, USERS, db_manager
from core.permissions import IsSuperAdmin, IsOrgAdmin, IsReadOnlyUser
from core.authentication import log_audit_event


class OrganizationListCreateView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request):
        db = get_db()
        if request.user.role == "super_admin":
            orgs = list(db[ORGANIZATIONS].find())
        else:
            org_id = request.user.organization_id
            orgs = list(db[ORGANIZATIONS].find({"_id": ObjectId(org_id)})) if org_id else []
        return Response(db_manager.serialize_doc(orgs))

    def post(self, request):
        if request.user.role != "super_admin":
            return Response({"error": "Only super administrators can create new organizations."}, status=status.HTTP_403_FORBIDDEN)

        name = request.data.get("name", "").strip()
        description = request.data.get("description", "").strip()
        if not name:
            return Response({"error": "Organization name is required."}, status=status.HTTP_400_BAD_REQUEST)

        db = get_db()
        doc = {
            "name": name,
            "description": description,
            "created_by": str(request.user.id),
            "created_at": datetime.utcnow()
        }
        res = db[ORGANIZATIONS].insert_one(doc)
        doc["id"] = str(res.inserted_id)
        log_audit_event(request.user.id, "ORG_CREATED", {"name": name}, organization_id=str(res.inserted_id))
        return Response(db_manager.serialize_doc(doc), status=status.HTTP_201_CREATED)


class OrganizationDetailView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request, pk):
        db = get_db()
        try:
            org = db[ORGANIZATIONS].find_one({"_id": ObjectId(pk)})
        except Exception:
            org = None
        if not org:
            return Response({"error": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user.role != "super_admin" and str(org["_id"]) != request.user.organization_id:
            return Response({"error": "Unauthorized access to this organization."}, status=status.HTTP_403_FORBIDDEN)

        members = list(db[USERS].find({"organization_id": str(org["_id"])}, {"password_hash": 0, "totp_secret": 0}))
        data = db_manager.serialize_doc(org)
        data["members"] = db_manager.serialize_doc(members)
        return Response(data)
