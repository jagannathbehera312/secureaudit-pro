"""
SecureAudit Pro - Live Threat & Attack Surface Monitoring API Views
"""

import logging
from datetime import datetime
from bson import ObjectId
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

from core.database import get_db, MONITOR_TARGETS, THREAT_EVENTS, MONITOR_METRICS
from security_engine.monitor_engine import normalize_target_input, run_perimeter_threat_audit

logger = logging.getLogger(__name__)


def serialize_doc(doc: dict) -> dict:
    if not doc:
        return {}
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    elif "id" not in doc:
        doc["id"] = str(ObjectId())
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
        elif isinstance(v, ObjectId):
            doc[k] = str(v)
    return doc


class MonitorTargetListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        db = get_db()
        targets = list(db[MONITOR_TARGETS].find().sort("created_at", -1))
        serialized = [serialize_doc(t) for t in targets]

        # Calculate high-level posture stats
        total_targets = len(serialized)
        healthy_count = sum(1 for t in serialized if t.get("status") == "healthy")
        threat_count = db[THREAT_EVENTS].count_documents({"status": "active"})
        avg_latency = round(
            sum(t.get("latency_ms", 45.0) for t in serialized) / max(1, total_targets), 1
        ) if total_targets > 0 else 0.0

        return Response({
            "targets": serialized,
            "summary": {
                "total_monitored": total_targets,
                "healthy_count": healthy_count,
                "active_threats": threat_count,
                "avg_latency_ms": avg_latency
            }
        })

    def post(self, request):
        raw_target = request.data.get("target") or request.data.get("url") or request.data.get("ip")
        name = request.data.get("name") or ""
        interval = int(request.data.get("interval_minutes", 5))

        if not raw_target:
            return Response({"error": "Target IP or URL is required."}, status=status.HTTP_400_BAD_REQUEST)

        parsed = normalize_target_input(raw_target)
        if not name:
            name = f"Asset {parsed['host']}"

        db = get_db()

        # Check if already monitored
        existing = db[MONITOR_TARGETS].find_one({"host": parsed["host"]})
        if existing:
            return Response({"error": f"Target '{parsed['host']}' is already under active threat monitoring."}, status=status.HTTP_400_BAD_REQUEST)

        # Create monitor document
        monitor_doc = {
            "name": name,
            "raw_input": parsed["raw_input"],
            "host": parsed["host"],
            "port": parsed["port"],
            "scheme": parsed["scheme"],
            "canonical_url": parsed["canonical_url"],
            "is_ip": parsed["is_ip"],
            "interval_minutes": interval,
            "status": "initializing",
            "threat_score": 100,
            "latency_ms": 0.0,
            "http_status": 0,
            "content_hash": "",
            "baseline_hash": "",
            "open_ports": [],
            "created_by": str(request.user.id) if hasattr(request.user, "id") else "analyst",
            "created_at": datetime.utcnow(),
            "last_checked_at": None
        }

        res = db[MONITOR_TARGETS].insert_one(monitor_doc)
        monitor_id = str(res.inserted_id)

        # Perform initial baseline audit
        audit_res = run_perimeter_threat_audit(
            monitor_id=monitor_id,
            host=parsed["host"],
            canonical_url=parsed["canonical_url"]
        )

        # Update monitor with baseline
        db[MONITOR_TARGETS].update_one(
            {"_id": ObjectId(monitor_id)},
            {
                "$set": {
                    "status": audit_res["status"],
                    "threat_score": audit_res["threat_score"],
                    "latency_ms": audit_res["latency_ms"],
                    "http_status": audit_res["http_status"],
                    "content_hash": audit_res["content_hash"],
                    "baseline_hash": audit_res["content_hash"],
                    "dom_title": audit_res["dom_title"],
                    "open_ports": audit_res["open_ports"],
                    "last_checked_at": audit_res["last_checked_at"]
                }
            }
        )

        updated = db[MONITOR_TARGETS].find_one({"_id": ObjectId(monitor_id)})
        return Response(serialize_doc(updated), status=status.HTTP_201_CREATED)


class MonitorTargetDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        db = get_db()
        try:
            target = db[MONITOR_TARGETS].find_one({"_id": ObjectId(pk)})
        except Exception:
            return Response({"error": "Invalid target ID."}, status=status.HTTP_404_NOT_FOUND)

        if not target:
            return Response({"error": "Monitored target not found."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve recent threat events
        threats = list(db[THREAT_EVENTS].find({"monitor_id": str(pk)}).sort("created_at", -1).limit(20))
        # Retrieve recent metrics
        metrics = list(db[MONITOR_METRICS].find({"monitor_id": str(pk)}).sort("timestamp", -1).limit(25))

        data = serialize_doc(target)
        data["recent_threats"] = [serialize_doc(th) for th in threats]
        data["recent_metrics"] = [serialize_doc(m) for m in metrics]

        return Response(data)

    def delete(self, request, pk):
        db = get_db()
        try:
            db[MONITOR_TARGETS].delete_one({"_id": ObjectId(pk)})
            db[THREAT_EVENTS].delete_many({"monitor_id": str(pk)})
            db[MONITOR_METRICS].delete_many({"monitor_id": str(pk)})
            return Response({"message": "Target removed from continuous monitoring."})
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class MonitorTargetCheckNowView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        db = get_db()
        try:
            target = db[MONITOR_TARGETS].find_one({"_id": ObjectId(pk)})
        except Exception:
            return Response({"error": "Invalid target ID."}, status=status.HTTP_404_NOT_FOUND)

        if not target:
            return Response({"error": "Target not found."}, status=status.HTTP_404_NOT_FOUND)

        audit_res = run_perimeter_threat_audit(
            monitor_id=str(pk),
            host=target["host"],
            canonical_url=target.get("canonical_url", f"http://{target['host']}/"),
            baseline_hash=target.get("baseline_hash")
        )

        db[MONITOR_TARGETS].update_one(
            {"_id": ObjectId(pk)},
            {
                "$set": {
                    "status": audit_res["status"],
                    "threat_score": audit_res["threat_score"],
                    "latency_ms": audit_res["latency_ms"],
                    "http_status": audit_res["http_status"],
                    "content_hash": audit_res["content_hash"],
                    "dom_title": audit_res["dom_title"],
                    "open_ports": audit_res["open_ports"],
                    "last_checked_at": audit_res["last_checked_at"]
                }
            }
        )

        updated = db[MONITOR_TARGETS].find_one({"_id": ObjectId(pk)})
        res_data = serialize_doc(updated)
        res_data["new_threats"] = [serialize_doc(th) for th in audit_res["threats_detected"]]
        return Response(res_data)


class ThreatEventsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        db = get_db()
        query = {}
        target_id = request.query_params.get("monitor_id")
        status_param = request.query_params.get("status")
        severity_param = request.query_params.get("severity")

        if target_id:
            query["monitor_id"] = str(target_id)
        if status_param and status_param != "all":
            query["status"] = status_param
        if severity_param and severity_param != "all":
            query["severity"] = severity_param

        events = list(db[THREAT_EVENTS].find(query).sort("created_at", -1).limit(50))
        return Response([serialize_doc(e) for e in events])


class ThreatEventResolveView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        db = get_db()
        notes = request.data.get("resolution_notes", "Mitigated by security analyst.")
        try:
            res = db[THREAT_EVENTS].update_one(
                {"_id": ObjectId(pk)},
                {
                    "$set": {
                        "status": "resolved",
                        "resolved_at": datetime.utcnow(),
                        "resolution_notes": notes
                    }
                }
            )
            if res.matched_count == 0:
                return Response({"error": "Threat event not found."}, status=status.HTTP_404_NOT_FOUND)
            return Response({"message": "Threat incident marked as resolved."})
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
