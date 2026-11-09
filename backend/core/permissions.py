"""
SecureAudit Pro - Role-Based Access Control (RBAC) Permissions
Enforces strict role hierarchies and multi-tenant organization boundary checks.
"""

from rest_framework import permissions


class IsSuperAdmin(permissions.BasePermission):
    """Allows access only to global Super Administrators."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == "super_admin")


class IsOrgAdmin(permissions.BasePermission):
    """Allows access to Super Administrators and Organization Administrators."""
    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated and 
            request.user.role in ("super_admin", "org_admin")
        )


class IsSecurityAnalyst(permissions.BasePermission):
    """Allows access to Super Admins, Org Admins, and Security Analysts (can initiate scans, review findings)."""
    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated and 
            request.user.role in ("super_admin", "org_admin", "security_analyst")
        )


class IsReadOnlyUser(permissions.BasePermission):
    """Allows read-only viewers and higher roles to access view-only resources."""
    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated and 
            request.user.role in ("super_admin", "org_admin", "security_analyst", "read_only")
        )


class CanInitiateScan(permissions.BasePermission):
    """Ensures read-only users cannot trigger scans or modify security targets."""
    def has_permission(self, request, view):
        return bool(
            request.user and request.user.is_authenticated and 
            request.user.role in ("super_admin", "org_admin", "security_analyst")
        )


def enforce_org_scope(request, query_dict: dict, org_field: str = "organization_id") -> dict:
    """Helper to enforce organization tenancy: non-super_admin users can only view their own org's data."""
    if not request.user.is_authenticated:
        return query_dict
    if request.user.role != "super_admin" and request.user.organization_id:
        query_dict[org_field] = request.user.organization_id
    return query_dict
