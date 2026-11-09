"""
SecureAudit Pro - Authentication Backend, JWT Handling, Password Security & TOTP 2FA
Integrates with MongoDB users collection.
"""

import hmac
import hashlib
import base64
import time
import struct
import secrets
from datetime import datetime, timedelta
import jwt
from django.conf import settings
from rest_framework import authentication, exceptions
from bson import ObjectId
from core.database import get_db, USERS, AUDIT_LOGS


def hash_password(password: str) -> str:
    """Secure password hashing using PBKDF2-HMAC-SHA256 with 260,000 iterations and salt."""
    salt = secrets.token_hex(16)
    kdf = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        260000
    )
    return f"pbkdf2_sha256$260000${salt}${base64.b64encode(kdf).decode('ascii')}"


def verify_password(plain_password: str, hashed: str) -> bool:
    """Verifies a plain password against the stored PBKDF2 hash."""
    try:
        algorithm, iterations, salt, hash_val = hashed.split("$")
        iterations = int(iterations)
        expected_bytes = base64.b64decode(hash_val.encode("ascii"))
        actual_bytes = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations
        )
        return hmac.compare_digest(expected_bytes, actual_bytes)
    except Exception:
        return False


# --- RFC 6238 TOTP Two-Factor Authentication ---

def generate_totp_secret() -> str:
    """Generates a base32 encoded random 160-bit secret for TOTP."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(chars) for _ in range(32))


def get_totp_token(secret: str, interval: int = 30) -> str:
    """Computes current 6-digit TOTP token."""
    try:
        # Base32 decode secret
        key = base64.b32decode(secret.upper(), casefold=True)
        counter = int(time.time() // interval)
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
        return f"{code:06d}"
    except Exception:
        return ""


def verify_totp_token(secret: str, user_code: str, window: int = 1) -> bool:
    """Verifies TOTP token allowing +/- 1 window interval for clock drift."""
    if not secret or not user_code or len(user_code.strip()) != 6:
        return False
    user_code = user_code.strip()
    key = base64.b32decode(secret.upper(), casefold=True)
    current_interval = int(time.time() // 30)
    for offset in range(-window, window + 1):
        msg = struct.pack(">Q", current_interval + offset)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        off = h[-1] & 0x0F
        code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % 1000000
        if f"{code:06d}" == user_code:
            return True
    return False


# --- JWT Token Generation & Verification ---

try:
    from django.conf import settings
    JWT_SECRET = getattr(settings, "SECRET_KEY", "secureaudit-default-jwt-secret-key-change-in-prod")
except Exception:
    JWT_SECRET = "secureaudit-default-jwt-secret-key-change-in-prod"

JWT_ALGORITHM = "HS256"


def create_jwt_tokens(user_doc: dict) -> dict:
    now = datetime.utcnow()
    user_id = str(user_doc["_id"])
    access_payload = {
        "user_id": user_id,
        "email": user_doc["email"],
        "role": user_doc.get("role", "security_analyst"),
        "org_id": str(user_doc.get("organization_id", "")),
        "type": "access",
        "exp": now + timedelta(hours=8),
        "iat": now
    }
    refresh_payload = {
        "user_id": user_id,
        "type": "refresh",
        "exp": now + timedelta(days=7),
        "iat": now
    }

    access_token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "access": access_token,
        "refresh": refresh_token,
        "expires_in": 28800
    }


def decode_jwt_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed("Token has expired.")
    except jwt.InvalidTokenError:
        raise exceptions.AuthenticationFailed("Invalid token.")


class MongoUser:
    """Wrapper around MongoDB user document to integrate with DRF request.user."""
    def __init__(self, doc: dict):
        self.doc = doc
        self.id = str(doc.get("_id", ""))
        self.email = doc.get("email", "")
        self.first_name = doc.get("first_name", "")
        self.last_name = doc.get("last_name", "")
        self.full_name = f"{self.first_name} {self.last_name}".strip() or self.email
        self.role = doc.get("role", "security_analyst")
        self.organization_id = str(doc.get("organization_id", ""))
        self.is_active = doc.get("is_active", True)
        self.totp_enabled = doc.get("totp_enabled", False)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    @property
    def is_staff(self):
        return self.role in ("super_admin", "org_admin")

    @property
    def is_superuser(self):
        return self.role == "super_admin"

    def __str__(self):
        return f"{self.email} ({self.role})"


class MongoJWTAuthentication(authentication.BaseAuthentication):
    """DRF Authentication class that parses 'Authorization: Bearer <token>' and looks up user in MongoDB."""

    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = ""
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        elif hasattr(request, "query_params") and "token" in request.query_params:
            token = request.query_params.get("token", "").strip()
        elif hasattr(request, "query_params") and "auth" in request.query_params:
            token = request.query_params.get("auth", "").strip()
        elif "token" in request.GET:
            token = request.GET.get("token", "").strip()

        if not token:
            return None

        payload = decode_jwt_token(token)

        if payload.get("type") != "access":
            raise exceptions.AuthenticationFailed("Invalid token type for authorization.")

        user_id = payload.get("user_id")
        if not user_id:
            raise exceptions.AuthenticationFailed("Token missing user identity.")

        db = get_db()
        try:
            user_doc = db[USERS].find_one({"_id": ObjectId(user_id)})
        except Exception:
            user_doc = None

        if not user_doc:
            raise exceptions.AuthenticationFailed("User not found or has been removed.")

        if not user_doc.get("is_active", True):
            raise exceptions.AuthenticationFailed("User account is suspended.")

        user = MongoUser(user_doc)
        return (user, token)


def log_audit_event(user_id: str, action: str, details: dict, organization_id: str = "", ip_address: str = ""):
    """Records an immutable security audit event into the audit_logs collection."""
    try:
        db = get_db()
        db[AUDIT_LOGS].insert_one({
            "user_id": str(user_id) if user_id else "system",
            "organization_id": str(organization_id),
            "action": action,
            "details": details,
            "ip_address": ip_address,
            "created_at": datetime.utcnow()
        })
    except Exception as e:
        pass
