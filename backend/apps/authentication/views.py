"""
SecureAudit Pro - Authentication API Views
Handles user registration, login with TOTP 2FA, JWT token refresh, profile management, and sessions.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from bson import ObjectId
from datetime import datetime

from core.database import get_db, USERS, ORGANIZATIONS, AUDIT_LOGS, db_manager
from core.authentication import (
    hash_password, verify_password, create_jwt_tokens, decode_jwt_token,
    generate_totp_secret, verify_totp_token, get_totp_token, log_audit_event
)
from core.permissions import IsSuperAdmin, IsOrgAdmin


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        data = request.data
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()
        org_name = data.get("organization_name", "").strip() or "Default Organization"
        role = data.get("role", "security_analyst")

        if not email or "@" not in email:
            return Response({"error": "A valid email address is required."}, status=status.HTTP_400_BAD_REQUEST)
        if len(password) < 8:
            return Response({"error": "Password must be at least 8 characters long."}, status=status.HTTP_400_BAD_REQUEST)

        db = get_db()
        if db[USERS].find_one({"email": email}):
            return Response({"error": "An account with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

        # Create or find organization
        org = db[ORGANIZATIONS].find_one({"name": org_name})
        if not org:
            org_res = db[ORGANIZATIONS].insert_one({
                "name": org_name,
                "created_at": datetime.utcnow()
            })
            org_id = str(org_res.inserted_id)
        else:
            org_id = str(org["_id"])

        user_doc = {
            "email": email,
            "password_hash": hash_password(password),
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
            "organization_id": org_id,
            "is_active": True,
            "totp_enabled": False,
            "totp_secret": None,
            "created_at": datetime.utcnow(),
            "last_login": None
        }
        res = db[USERS].insert_one(user_doc)
        user_doc["_id"] = res.inserted_id

        tokens = create_jwt_tokens(user_doc)
        log_audit_event(str(res.inserted_id), "USER_REGISTERED", {"email": email, "role": role}, organization_id=org_id)

        return Response({
            "message": "User registered successfully.",
            "user": {
                "id": str(res.inserted_id),
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "role": role,
                "organization_id": org_id,
                "totp_enabled": False
            },
            "tokens": tokens
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email", "").strip().lower()
        password = request.data.get("password", "")
        totp_code = request.data.get("totp_code", "").strip()

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        db = get_db()
        user = db[USERS].find_one({"email": email})
        if not user or not verify_password(password, user.get("password_hash", "")):
            log_audit_event("", "LOGIN_FAILED", {"email": email, "reason": "invalid_credentials"})
            return Response({"error": "Invalid email or password credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.get("is_active", True):
            return Response({"error": "This account has been suspended."}, status=status.HTTP_403_FORBIDDEN)

        # Check 2FA if enabled
        if user.get("totp_enabled"):
            if not totp_code:
                return Response({
                    "two_factor_required": True,
                    "message": "Enter your 6-digit TOTP two-factor authentication code."
                }, status=status.HTTP_200_OK)
            if not verify_totp_token(user.get("totp_secret", ""), totp_code):
                log_audit_event(str(user["_id"]), "2FA_FAILED", {"email": email})
                return Response({"error": "Invalid 2FA authentication code."}, status=status.HTTP_401_UNAUTHORIZED)

        # Update last login
        db[USERS].update_one({"_id": user["_id"]}, {"$set": {"last_login": datetime.utcnow()}})
        tokens = create_jwt_tokens(user)
        log_audit_event(str(user["_id"]), "LOGIN_SUCCESS", {"email": email}, organization_id=str(user.get("organization_id", "")))

        return Response({
            "message": "Login successful.",
            "user": {
                "id": str(user["_id"]),
                "email": user["email"],
                "first_name": user.get("first_name", ""),
                "last_name": user.get("last_name", ""),
                "role": user.get("role", "security_analyst"),
                "organization_id": str(user.get("organization_id", "")),
                "totp_enabled": user.get("totp_enabled", False)
            },
            "tokens": tokens
        })


class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh", "")
        if not refresh_token:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = decode_jwt_token(refresh_token)
            if payload.get("type") != "refresh":
                return Response({"error": "Invalid token type."}, status=status.HTTP_400_BAD_REQUEST)

            db = get_db()
            user = db[USERS].find_one({"_id": ObjectId(payload.get("user_id"))})
            if not user or not user.get("is_active", True):
                return Response({"error": "User inactive or not found."}, status=status.HTTP_401_UNAUTHORIZED)

            tokens = create_jwt_tokens(user)
            return Response(tokens)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)


class ProfileView(APIView):
    def get(self, request):
        user = request.user
        db = get_db()
        user_doc = db[USERS].find_one({"_id": ObjectId(user.id)})
        org_doc = db[ORGANIZATIONS].find_one({"_id": ObjectId(user.organization_id)}) if user.organization_id else None
        
        return Response({
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            "organization_id": user.organization_id,
            "organization_name": org_doc.get("name") if org_doc else "Independent",
            "totp_enabled": user.totp_enabled,
            "created_at": db_manager.serialize_doc(user_doc.get("created_at")) if user_doc else None,
            "last_login": db_manager.serialize_doc(user_doc.get("last_login")) if user_doc else None
        })

    def put(self, request):
        user = request.user
        first_name = request.data.get("first_name", user.first_name).strip()
        last_name = request.data.get("last_name", user.last_name).strip()

        db = get_db()
        db[USERS].update_one(
            {"_id": ObjectId(user.id)},
            {"$set": {"first_name": first_name, "last_name": last_name}}
        )
        return Response({"message": "Profile updated successfully."})


class ChangePasswordView(APIView):
    def post(self, request):
        user = request.user
        if not user or not getattr(user, "is_authenticated", False):
            return Response({"error": "Authentication required. Please log in."}, status=status.HTTP_401_UNAUTHORIZED)

        current_password = request.data.get("current_password", "")
        new_password = request.data.get("new_password", "")

        if not current_password:
            return Response({"error": "Current password is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not new_password:
            return Response({"error": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)

        if len(new_password) < 8:
            return Response({"error": "New password must be at least 8 characters long."}, status=status.HTTP_400_BAD_REQUEST)

        if current_password == new_password:
            return Response({"error": "New password cannot be identical to your current password."}, status=status.HTTP_400_BAD_REQUEST)

        db = get_db()
        user_doc = None
        user_id_val = getattr(user, "id", None) or getattr(user, "pk", None)
        if user_id_val:
            try:
                user_doc = db[USERS].find_one({"_id": ObjectId(str(user_id_val))})
            except Exception:
                pass
            if not user_doc:
                user_doc = db[USERS].find_one({"_id": str(user_id_val)})

        if not user_doc and getattr(user, "email", None):
            user_doc = db[USERS].find_one({"email": user.email.strip().lower()})

        if not user_doc:
            return Response({"error": "User account not found in database."}, status=status.HTTP_404_NOT_FOUND)

        if not verify_password(current_password, user_doc.get("password_hash", "")):
            return Response({"error": "Current password is incorrect. Please verify and try again."}, status=status.HTTP_400_BAD_REQUEST)

        db[USERS].update_one(
            {"_id": user_doc["_id"]},
            {"$set": {"password_hash": hash_password(new_password)}}
        )
        log_audit_event(str(user_doc["_id"]), "PASSWORD_CHANGED", {"email": user.email}, organization_id=str(getattr(user, "organization_id", "")))
        return Response({"message": "Password changed successfully."})


class TOTPSetupView(APIView):
    def post(self, request):
        user = request.user
        secret = generate_totp_secret()
        db = get_db()
        db[USERS].update_one({"_id": ObjectId(user.id)}, {"$set": {"pending_totp_secret": secret}})
        current_code = get_totp_token(secret)
        otpauth_url = f"otpauth://totp/SecureAuditPro:{user.email}?secret={secret}&issuer=SecureAuditPro"
        return Response({
            "secret": secret,
            "otpauth_url": otpauth_url,
            "sample_current_code": current_code,
            "instructions": "Scan QR or enter secret in Authenticator app, then submit the 6-digit code to /api/auth/2fa/verify/."
        })


class TOTPVerifyView(APIView):
    def post(self, request):
        user = request.user
        code = request.data.get("code", "")
        db = get_db()
        user_doc = db[USERS].find_one({"_id": ObjectId(user.id)})
        pending_secret = user_doc.get("pending_totp_secret")
        if not pending_secret:
            return Response({"error": "No pending 2FA setup found. Call /api/auth/2fa/setup/ first."}, status=status.HTTP_400_BAD_REQUEST)

        if verify_totp_token(pending_secret, code):
            db[USERS].update_one(
                {"_id": ObjectId(user.id)},
                {"$set": {"totp_enabled": True, "totp_secret": pending_secret, "pending_totp_secret": None}}
            )
            log_audit_event(user.id, "2FA_ENABLED", {"email": user.email}, organization_id=user.organization_id)
            return Response({"message": "Two-factor authentication enabled successfully."})
        return Response({"error": "Invalid verification code."}, status=status.HTTP_400_BAD_REQUEST)


class UsersAdminListView(APIView):
    permission_classes = [IsOrgAdmin]

    def get(self, request):
        db = get_db()
        query = {}
        if request.user.role != "super_admin":
            query["organization_id"] = request.user.organization_id

        users = list(db[USERS].find(query, {"password_hash": 0, "totp_secret": 0}))
        return Response(db_manager.serialize_doc(users))
