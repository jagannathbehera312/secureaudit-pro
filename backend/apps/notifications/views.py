"""
SecureAudit Pro - In-App Notification System API Views
Delivers security alerts, scan completion notices, and remediation updates.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from bson import ObjectId
from datetime import datetime

from core.database import get_db, NOTIFICATIONS, db_manager
from core.permissions import IsReadOnlyUser


class NotificationListView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request):
        db = get_db()
        user_id = str(request.user.id)
        org_id = request.user.organization_id

        # Query user notifications or organization-wide notifications
        query = {
            "$or": [
                {"user_id": user_id},
                {"organization_id": org_id, "user_id": None}
            ]
        }
        notifs = list(db[NOTIFICATIONS].find(query).sort("created_at", -1).limit(30))
        return Response(db_manager.serialize_doc(notifs))


class NotificationMarkReadView(APIView):
    permission_classes = [IsReadOnlyUser]

    def post(self, request, pk):
        db = get_db()
        db[NOTIFICATIONS].update_one(
            {"_id": ObjectId(pk)},
            {"$set": {"read": True, "read_at": datetime.utcnow()}}
        )
        return Response({"message": "Notification marked as read."})
