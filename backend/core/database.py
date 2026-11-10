"""
SecureAudit Pro - Database Access Layer
Supports production MongoDB via PyMongo with transparent fallback to mongomock
for zero-friction development and portable testing.
"""

import os
import logging
from datetime import datetime
from bson import ObjectId

logger = logging.getLogger(__name__)

# Collection Names
USERS = "users"
ORGANIZATIONS = "organizations"
ORG_MEMBERS = "organization_members"
WEBSITES = "websites"
DOMAIN_AUTH = "domain_authorizations"
SCAN_PROFILES = "scan_profiles"
SCAN_JOBS = "scan_jobs"
SCAN_EVENTS = "scan_events"
SCAN_RESULTS = "scan_results"
VULNERABILITIES = "vulnerabilities"
VULN_EVIDENCE = "vulnerability_evidence"
REMEDIATION_TASKS = "remediation_tasks"
REPORTS = "reports"
SCHEDULED_SCANS = "scheduled_scans"
NOTIFICATIONS = "notifications"
AUDIT_LOGS = "audit_logs"
SCANNER_CONFIGS = "scanner_configurations"
SYSTEM_SETTINGS = "system_settings"
MONITOR_TARGETS = "monitor_targets"
THREAT_EVENTS = "threat_events"
MONITOR_METRICS = "monitor_metrics"

COLLECTIONS = [
    USERS, ORGANIZATIONS, ORG_MEMBERS, WEBSITES, DOMAIN_AUTH,
    SCAN_PROFILES, SCAN_JOBS, SCAN_EVENTS, SCAN_RESULTS,
    VULNERABILITIES, VULN_EVIDENCE, REMEDIATION_TASKS, REPORTS,
    SCHEDULED_SCANS, NOTIFICATIONS, AUDIT_LOGS, SCANNER_CONFIGS, SYSTEM_SETTINGS,
    MONITOR_TARGETS, THREAT_EVENTS, MONITOR_METRICS
]


class MongoDBManager:
    _instance = None
    _client = None
    _db = None
    _is_mock = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MongoDBManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        mongo_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
        db_name = os.environ.get("MONGODB_DB_NAME", "secureaudit_pro")

        use_mock = os.environ.get("USE_MOCK_DB", "").lower() in ("true", "1", "yes")

        if not use_mock:
            try:
                import pymongo

                # Construct authenticated URI if credentials exist and URI is unauthenticated
                user = os.environ.get("MONGO_INITDB_ROOT_USERNAME") or os.environ.get("MONGODB_USER")
                pwd = os.environ.get("MONGO_INITDB_ROOT_PASSWORD") or os.environ.get("MONGODB_PASSWORD")
                if user and pwd and "@" not in mongo_uri:
                    prefix = "mongodb://"
                    if mongo_uri.startswith(prefix):
                        rest = mongo_uri[len(prefix):]
                        mongo_uri = f"{prefix}{user}:{pwd}@{rest}"
                        if "?" not in mongo_uri:
                            mongo_uri += "?authSource=admin"

                # Try connecting with a short timeout to verify live connectivity
                client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=1500)
                client.server_info()  # Will trigger exception if not reachable

                # Verify actual database authorization (will fail if auth required and missing/wrong)
                client[db_name].command("ping")
                client[db_name][USERS].find_one()

                self._client = client
                self._db = client[db_name]
                self._is_mock = False
                logger.info(f"Connected to live MongoDB at {mongo_uri}, database: {db_name}")
            except Exception as e:
                logger.warning(f"Could not connect to live MongoDB ({e}). Falling back to in-memory mongomock.")
                self._init_mock(db_name)
        else:
            self._init_mock(db_name)

        self._ensure_indexes()

    def _init_mock(self, db_name):
        try:
            import mongomock
            self._client = mongomock.MongoClient()
            self._db = self._client[db_name]
            self._is_mock = True
            logger.info(f"Using in-memory mongomock database: {db_name}")
        except ImportError:
            raise RuntimeError("Neither pymongo connection nor mongomock is available.")

    def _ensure_indexes(self):
        """Creates proper compound and unique indexes for high-frequency queries."""
        try:
            # Users
            self._db[USERS].create_index("email", unique=True)
            self._db[USERS].create_index("organization_id")
            
            # Websites
            self._db[WEBSITES].create_index([("organization_id", 1), ("domain", 1)])
            self._db[WEBSITES].create_index("verification_status")

            # Scan Jobs
            self._db[SCAN_JOBS].create_index([("website_id", 1), ("created_at", -1)])
            self._db[SCAN_JOBS].create_index("status")
            self._db[SCAN_JOBS].create_index("organization_id")

            # Scan Events
            self._db[SCAN_EVENTS].create_index([("scan_id", 1), ("timestamp", 1)])

            # Vulnerabilities
            self._db[VULNERABILITIES].create_index("dedup_key", unique=True)
            self._db[VULNERABILITIES].create_index([("website_id", 1), ("severity", 1)])
            self._db[VULNERABILITIES].create_index([("scan_id", 1), ("severity", 1)])
            self._db[VULNERABILITIES].create_index("status")
            self._db[VULNERABILITIES].create_index("owasp_category")

            # Remediation Tasks
            self._db[REMEDIATION_TASKS].create_index([("website_id", 1), ("status", 1)])
            self._db[REMEDIATION_TASKS].create_index("assigned_to")

            # Reports
            self._db[REPORTS].create_index([("website_id", 1), ("created_at", -1)])

            # Audit Logs
            self._db[AUDIT_LOGS].create_index([("created_at", -1)])
            self._db[AUDIT_LOGS].create_index("user_id")
            self._db[AUDIT_LOGS].create_index("organization_id")
        except Exception as e:
            logger.warning(f"Error creating indexes: {e}")

    @property
    def db(self):
        return self._db

    @property
    def is_mock(self):
        return self._is_mock

    def get_collection(self, name: str):
        return self._db[name]

    def serialize_doc(self, doc):
        """Helper to convert MongoDB ObjectId and datetimes to JSON-compatible types."""
        if doc is None:
            return None
        if isinstance(doc, list):
            return [self.serialize_doc(item) for item in doc]
        if not doc:
            return doc
        if not isinstance(doc, dict):
            return doc

        clean = {}
        for k, v in doc.items():
            if k == "_id":
                clean["id"] = str(v)
            elif isinstance(v, ObjectId):
                clean[k] = str(v)
            elif isinstance(v, datetime):
                clean[k] = v.isoformat()
            elif isinstance(v, dict):
                clean[k] = self.serialize_doc(v)
            elif isinstance(v, list):
                clean[k] = [self.serialize_doc(item) for item in v]
            else:
                clean[k] = v
        return clean

    def to_object_id(self, id_str):
        if isinstance(id_str, ObjectId):
            return id_str
        try:
            return ObjectId(id_str)
        except Exception:
            return None


# Global singleton instance
db_manager = MongoDBManager()
get_db = lambda: db_manager.db
