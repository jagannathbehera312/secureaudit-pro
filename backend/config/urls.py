"""
SecureAudit Pro - Main API URL Routing
"""

from django.urls import path
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from apps.authentication.views import (
    RegisterView, LoginView, RefreshTokenView, ProfileView,
    ChangePasswordView, TOTPSetupView, TOTPVerifyView, UsersAdminListView
)
from apps.organizations.views import OrganizationListCreateView, OrganizationDetailView
from apps.websites.views import (
    WebsiteListCreateView, WebsiteDetailView, WebsiteVerifyChallengeView
)
from apps.scanning.views import (
    ScanListCreateView, ScanDetailView, ScanStopView, ScanRetryView,
    ScanEventsView, ScanResultsView, ScanCompareView
)
from apps.vulnerabilities.views import (
    VulnerabilityListView, VulnerabilityDetailView,
    VulnerabilityCommentView, VulnerabilityRetestView
)
from apps.remediation.views import RemediationListCreateView, RemediationDetailView
from apps.reports.views import ReportListCreateView, ReportDownloadView
from apps.administration.views import (
    AdminDashboardStatsView, SystemHealthView, AuditLogsView, ResetDemoDataView
)
from apps.notifications.views import NotificationListView, NotificationMarkReadView
from apps.monitoring.views import (
    MonitorTargetListCreateView, MonitorTargetDetailView, MonitorTargetCheckNowView,
    ThreatEventsListView, ThreatEventResolveView
)


class HealthCheckView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        return Response({
            "status": "healthy",
            "service": "SecureAudit Pro Backend API",
            "version": "2.0.0",
            "tagline": "Discover Vulnerabilities. Strengthen Security. Protect Your Digital Assets."
        })


urlpatterns = [
    # System Health
    path("api/health/", HealthCheckView.as_view(), name="health_check"),

    # Authentication & User Management
    path("api/auth/register/", RegisterView.as_view(), name="auth_register"),
    path("api/auth/login/", LoginView.as_view(), name="auth_login"),
    path("api/auth/refresh/", RefreshTokenView.as_view(), name="auth_refresh"),
    path("api/auth/profile/", ProfileView.as_view(), name="auth_profile"),
    path("api/auth/change-password/", ChangePasswordView.as_view(), name="auth_change_password"),
    path("api/auth/2fa/setup/", TOTPSetupView.as_view(), name="auth_2fa_setup"),
    path("api/auth/2fa/verify/", TOTPVerifyView.as_view(), name="auth_2fa_verify"),
    path("api/auth/users/", UsersAdminListView.as_view(), name="auth_users_admin"),

    # Organizations
    path("api/organizations/", OrganizationListCreateView.as_view(), name="org_list_create"),
    path("api/organizations/<str:pk>/", OrganizationDetailView.as_view(), name="org_detail"),

    # Websites & Domain Authorization
    path("api/websites/", WebsiteListCreateView.as_view(), name="website_list_create"),
    path("api/websites/<str:pk>/", WebsiteDetailView.as_view(), name="website_detail"),
    path("api/websites/<str:pk>/verify/", WebsiteVerifyChallengeView.as_view(), name="website_verify"),

    # Security Scans
    path("api/scans/", ScanListCreateView.as_view(), name="scan_list_create"),
    path("api/scans/compare/", ScanCompareView.as_view(), name="scan_compare"),
    path("api/scans/<str:pk>/", ScanDetailView.as_view(), name="scan_detail"),
    path("api/scans/<str:pk>/stop/", ScanStopView.as_view(), name="scan_stop"),
    path("api/scans/<str:pk>/retry/", ScanRetryView.as_view(), name="scan_retry"),
    path("api/scans/<str:pk>/events/", ScanEventsView.as_view(), name="scan_events"),
    path("api/scans/<str:pk>/results/", ScanResultsView.as_view(), name="scan_results"),

    # Vulnerability Management
    path("api/vulnerabilities/", VulnerabilityListView.as_view(), name="vuln_list"),
    path("api/vulnerabilities/<str:pk>/", VulnerabilityDetailView.as_view(), name="vuln_detail"),
    path("api/vulnerabilities/<str:pk>/comments/", VulnerabilityCommentView.as_view(), name="vuln_comment"),
    path("api/vulnerabilities/<str:pk>/retest/", VulnerabilityRetestView.as_view(), name="vuln_retest"),

    # Remediation Tracking
    path("api/remediation/", RemediationListCreateView.as_view(), name="remediation_list_create"),
    path("api/remediation/<str:pk>/", RemediationDetailView.as_view(), name="remediation_detail"),

    # Reports
    path("api/reports/", ReportListCreateView.as_view(), name="report_list_create"),
    path("api/reports/<str:pk>/download/", ReportDownloadView.as_view(), name="report_download"),
    path("api/reports/<str:pk>/pdf/", ReportDownloadView.as_view(), name="report_download_pdf"),
    path("api/scans/<str:pk>/pdf/", ReportDownloadView.as_view(), name="scan_download_pdf"),

    # Administration
    path("api/admin/dashboard/", AdminDashboardStatsView.as_view(), name="admin_stats"),
    path("api/admin/system-health/", SystemHealthView.as_view(), name="admin_health"),
    path("api/admin/audit-logs/", AuditLogsView.as_view(), name="admin_audit_logs"),
    path("api/admin/reset-demo/", ResetDemoDataView.as_view(), name="admin_reset_demo"),
    path("api/admin/reset-data/", ResetDemoDataView.as_view(), name="admin_reset_data"),

    # In-App Notifications
    path("api/notifications/", NotificationListView.as_view(), name="notification_list"),
    path("api/notifications/<str:pk>/read/", NotificationMarkReadView.as_view(), name="notification_mark_read"),

    # Live Threat & Attack Surface Monitoring
    path("api/monitoring/", MonitorTargetListCreateView.as_view(), name="monitor_list_create"),
    path("api/monitoring/events/", ThreatEventsListView.as_view(), name="threat_events_list"),
    path("api/monitoring/events/<str:pk>/resolve/", ThreatEventResolveView.as_view(), name="threat_event_resolve"),
    path("api/monitoring/<str:pk>/", MonitorTargetDetailView.as_view(), name="monitor_detail"),
    path("api/monitoring/<str:pk>/check/", MonitorTargetCheckNowView.as_view(), name="monitor_check_now"),
]
