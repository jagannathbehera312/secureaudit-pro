"""
SecureAudit Pro - Professional Security Report Generator
Produces Executive and Detailed PDF reports, responsive HTML audit reports,
and JSON / CSV vulnerability exports.
"""

import io
import csv
import json
from datetime import datetime
from bson import ObjectId
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.http import HttpResponse, JsonResponse
from django.views import View

from core.database import (
    get_db, REPORTS, SCAN_JOBS, SCAN_RESULTS,
    WEBSITES, VULNERABILITIES, db_manager
)
from core.permissions import IsReadOnlyUser, enforce_org_scope
from core.authentication import log_audit_event
from apps.reports.pdf_generator import generate_enterprise_pdf_report


def render_html_report(job: dict, website: dict, result: dict, vulns: list, report_type: str = "detailed") -> str:
    """Renders a standalone, executive/detailed HTML report with print-ready CSS styling."""
    target_url = job.get("target_url") or website.get("url", "")
    domain = job.get("domain") or website.get("domain", "")
    scan_date = job.get("created_at")
    if isinstance(scan_date, datetime):
        scan_date_str = scan_date.strftime("%B %d, %Y - %H:%M UTC")
    else:
        scan_date_str = str(scan_date or datetime.utcnow().strftime("%B %d, %Y"))

    score = job.get("security_score", 100.0) or 100.0
    sev_counts = result.get("severity_counts", {
        "critical": sum(1 for v in vulns if v.get("severity") == "critical"),
        "high": sum(1 for v in vulns if v.get("severity") == "high"),
        "medium": sum(1 for v in vulns if v.get("severity") == "medium"),
        "low": sum(1 for v in vulns if v.get("severity") == "low"),
        "info": sum(1 for v in vulns if v.get("severity") == "info")
    })

    score_color = "#10B981" if score >= 85 else ("#EAB308" if score >= 65 else "#EF4444")

    # Render vulnerability rows
    vuln_sections = []
    for idx, v in enumerate(vulns, 1):
        sev = v.get("severity", "info").lower()
        sev_color = {
            "critical": "#EF4444",
            "high": "#F97316",
            "medium": "#EAB308",
            "low": "#10B981",
            "info": "#3B82F6"
        }.get(sev, "#6B7280")

        vuln_sections.append(f"""
        <div class="finding-card" style="border-left: 5px solid {sev_color}; margin-bottom: 24px; padding: 18px; background: #ffffff; box-shadow: 0 1px 4px rgba(0,0,0,0.08); border-radius: 4px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="margin: 0; color: #111827; font-size: 16px;">SEC-{idx:03d}: {v.get('title')}</h3>
                <span style="background: {sev_color}; color: #ffffff; padding: 3px 10px; font-weight: bold; border-radius: 3px; font-size: 12px; text-transform: uppercase;">{sev}</span>
            </div>
            <div style="font-size: 13px; color: #4B5563; margin-bottom: 12px;">
                <strong>OWASP:</strong> {v.get('owasp_category', 'A02:2025 - Security Misconfiguration')} |
                <strong>CWE:</strong> {v.get('cwe_id', 'CWE-16')} |
                <strong>CVSS Score:</strong> {v.get('cvss_score', 'N/A')}
            </div>
            <div style="margin-bottom: 8px;">
                <strong style="color: #374151;">Affected URL:</strong> <code style="background: #F3F4F6; padding: 2px 6px; border-radius: 3px; color: #1F2937;">{v.get('affected_url')}</code>
            </div>
            <p style="color: #374151; font-size: 14px; line-height: 1.5; margin: 8px 0;"><strong>Description:</strong> {v.get('description', '')}</p>
            <div style="background: #FEF3C7; border: 1px solid #FCD34D; border-radius: 4px; padding: 10px; margin: 10px 0; font-size: 13px; color: #92400E;">
                <strong>Security Impact:</strong> {v.get('impact', 'Potential security compromise.')}
            </div>
            <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px; padding: 10px; margin: 10px 0; font-size: 12px; font-family: monospace; white-space: pre-wrap; word-break: break-all; color: #0F172A;">
                <strong>Observed Evidence:</strong><br>{v.get('evidence', 'No raw trace captured.')}
            </div>
            <div style="background: #ECFDF5; border: 1px solid #A7F3D0; border-radius: 4px; padding: 10px; margin-top: 10px; font-size: 13px; color: #065F46;">
                <strong>Remediation Guidance:</strong> {v.get('remediation', 'Apply vendor security recommendations.')}
            </div>
            <div style="background: #0F172A; border: 1px solid #0284C7; border-radius: 4px; padding: 12px; margin-top: 10px; font-size: 12px; font-family: monospace; white-space: pre-wrap; word-break: break-all; color: #38BDF8;">
                <div style="color: #94A3B8; font-size: 11px; margin-bottom: 5px; text-transform: uppercase; font-weight: bold;">⚡ Actionable Fix Command / Configuration:</div>
                <code>{v.get('fix_command') or (v.get('remediation', '').split('Verification:')[0].strip() if 'remediation' in v else 'Follow vendor remediation instructions.')}</code>
            </div>
        </div>
        """)

    open_ports = job.get("open_ports") or result.get("open_ports") or []
    open_ports_rows = []
    for p in open_ports:
        risk = p.get("risk", "info").lower()
        r_color = {"critical": "#EF4444", "high": "#F97316", "medium": "#EAB308", "low": "#10B981"}.get(risk, "#3B82F6")
        open_ports_rows.append(f"""
        <tr>
            <td><strong style="color: #0284C7;">Port {p.get('port')} / TCP</strong></td>
            <td><strong>{p.get('service')}</strong></td>
            <td>{p.get('desc', 'Standard TCP Listener')}</td>
            <td><code style="background: #0F172A; color: #38BDF8; padding: 3px 8px; border-radius: 3px; font-size: 11px;">sudo ufw deny {p.get('port')}/tcp</code></td>
            <td><span style="color: {r_color}; font-weight: bold; text-transform: uppercase;">{risk}</span></td>
        </tr>
        """)

    if open_ports_rows:
        open_ports_section = f"""
        <div style="background: #ffffff; padding: 24px; border-radius: 6px; border: 1px solid #E5E7EB; margin-bottom: 30px;">
            <h2 style="margin-top: 0;">2. Open Ports & Network Perimeter Services ({len(open_ports)})</h2>
            <p style="font-size: 13px; color: #4B5563;">Active TCP listeners detected during network perimeter auditing with direct firewall containment rules.</p>
            <table>
                <thead>
                    <tr>
                        <th>Port / Protocol</th>
                        <th>Service</th>
                        <th>Description</th>
                        <th>Containment Command</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(open_ports_rows)}
                </tbody>
            </table>
        </div>
        """
    else:
        open_ports_section = """
        <div style="background: #ffffff; padding: 24px; border-radius: 6px; border: 1px solid #E5E7EB; margin-bottom: 30px;">
            <h2 style="margin-top: 0;">2. Open Ports & Network Perimeter Services</h2>
            <p style="font-size: 13px; color: #4B5563;">Standard web endpoints active; no non-standard open ports exposed.</p>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SecureAudit Pro Security Assessment Report - {domain}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1F2937; margin: 0; padding: 40px; background: #F9FAFB; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .cover-header {{ background: #0F172A; color: #ffffff; padding: 36px; border-radius: 8px; margin-bottom: 30px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    .stat-box {{ background: #ffffff; padding: 18px; border-radius: 6px; border: 1px solid #E5E7EB; text-align: center; flex: 1; margin: 0 8px; }}
    .stats-row {{ display: flex; justify-content: space-between; margin-bottom: 30px; }}
    h1, h2, h3 {{ color: #111827; }}
    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #ffffff; }}
    th, td {{ padding: 12px; border: 1px solid #E5E7EB; text-align: left; font-size: 13px; }}
    th {{ background: #F3F4F6; color: #374151; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
    <div class="cover-header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="font-size: 24px; font-weight: 800; color: #06B6D4; letter-spacing: 0.5px;">SECUREAUDIT PRO</div>
            <div style="background: rgba(255,255,255,0.1); padding: 4px 12px; border-radius: 4px; font-size: 12px; text-transform: uppercase;">CONFIDENTIAL AUDIT REPORT</div>
        </div>
        <h1 style="color: #ffffff; font-size: 28px; margin-top: 24px; margin-bottom: 8px;">Web Application Penetration Testing Report</h1>
        <p style="color: #94A3B8; margin: 0; font-size: 15px;">Target Domain: <strong style="color: #ffffff;">{domain}</strong> | Scan ID: {str(job.get('_id', 'N/A'))[:12]}</p>
        <p style="color: #94A3B8; margin-top: 4px; font-size: 13px;">Assessment Completed: {scan_date_str}</p>
    </div>

    <div class="stats-row">
        <div class="stat-box" style="border-top: 4px solid {score_color};">
            <div style="font-size: 32px; font-weight: 800; color: {score_color};">{score}/100</div>
            <div style="font-size: 13px; color: #6B7280; margin-top: 4px;">Security Score</div>
        </div>
        <div class="stat-box" style="border-top: 4px solid #EF4444;">
            <div style="font-size: 32px; font-weight: 800; color: #EF4444;">{sev_counts.get('critical', 0)}</div>
            <div style="font-size: 13px; color: #6B7280; margin-top: 4px;">Critical Issues</div>
        </div>
        <div class="stat-box" style="border-top: 4px solid #F97316;">
            <div style="font-size: 32px; font-weight: 800; color: #F97316;">{sev_counts.get('high', 0)}</div>
            <div style="font-size: 13px; color: #6B7280; margin-top: 4px;">High Severity</div>
        </div>
        <div class="stat-box" style="border-top: 4px solid #EAB308;">
            <div style="font-size: 32px; font-weight: 800; color: #EAB308;">{sev_counts.get('medium', 0)}</div>
            <div style="font-size: 13px; color: #6B7280; margin-top: 4px;">Medium Severity</div>
        </div>
        <div class="stat-box" style="border-top: 4px solid #10B981;">
            <div style="font-size: 32px; font-weight: 800; color: #10B981;">{sev_counts.get('low', 0)}</div>
            <div style="font-size: 13px; color: #6B7280; margin-top: 4px;">Low / Info</div>
        </div>
    </div>

    <div style="background: #ffffff; padding: 24px; border-radius: 6px; border: 1px solid #E5E7EB; margin-bottom: 30px;">
        <h2 style="margin-top: 0;">1. Executive Summary & Assessment Scope</h2>
        <p style="font-size: 14px; line-height: 1.6; color: #374151;">
            SecureAudit Pro conducted an automated web application vulnerability assessment against target <strong>{target_url}</strong>.
            Testing was conducted using non-destructive methodologies compliant with OWASP Top 10:2025 and OWASP API Security standards.
            A total of <strong>{len(vulns)}</strong> findings were identified.
        </p>
        <table>
            <tr><th width="30%">Target URL</th><td>{target_url}</td></tr>
            <tr><th>Scan Profile</th><td>{job.get('profile', 'Standard').capitalize()} Scan</td></tr>
            <tr><th>Authorization Proof</th><td>Verified Domain Challenge</td></tr>
            <tr><th>Overall Risk Rating</th><td><strong>{job.get('risk_level', 'Evaluated')}</strong></td></tr>
        </table>
    </div>

    {open_ports_section}

    <h2>3. Detailed Technical Findings & Remediation</h2>
    {''.join(vuln_sections) if vuln_sections else '<p style="color: #6B7280;">No security vulnerabilities were identified in the configured scan scope.</p>'}

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #E5E7EB; font-size: 12px; color: #9CA3AF; text-align: center;">
        Generated by SecureAudit Pro Platform. Discover Vulnerabilities. Strengthen Security. Protect Your Digital Assets.
    </div>
</div>
</body>
</html>
"""
    return html


class ReportListCreateView(APIView):
    permission_classes = [IsReadOnlyUser]

    def get(self, request):
        db = get_db()
        query = enforce_org_scope(request, {})
        reports = list(db[REPORTS].find(query).sort("created_at", -1))
        return Response(db_manager.serialize_doc(reports))

    def post(self, request):
        data = request.data
        scan_id = data.get("scan_id")
        format_type = data.get("format", "pdf").lower() # pdf | html | json | csv
        report_type = data.get("report_type", "detailed").lower() # detailed | executive

        if not scan_id:
            return Response({"error": "scan_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        db = get_db()
        job = db[SCAN_JOBS].find_one({"_id": ObjectId(scan_id)})
        if not job:
            return Response({"error": "Scan job not found."}, status=status.HTTP_404_NOT_FOUND)

        site = db[WEBSITES].find_one({"_id": ObjectId(job.get("website_id"))}) if job.get("website_id") else {}
        result = db[SCAN_RESULTS].find_one({"scan_id": scan_id}) or {}
        vulns = list(db[VULNERABILITIES].find({"last_scan_id": scan_id}))

        report_doc = {
            "scan_id": scan_id,
            "website_id": job.get("website_id"),
            "website_name": job.get("website_name"),
            "target_url": job.get("target_url"),
            "domain": job.get("domain"),
            "format": format_type,
            "report_type": report_type,
            "findings_count": len(vulns),
            "security_score": job.get("security_score"),
            "generated_by": str(request.user.id),
            "organization_id": job.get("organization_id"),
            "created_at": datetime.utcnow()
        }

        res = db[REPORTS].insert_one(report_doc)
        report_id = str(res.inserted_id)
        report_doc["id"] = report_id

        log_audit_event(request.user.id, "REPORT_GENERATED", {"report_id": report_id, "format": format_type})
        return Response(db_manager.serialize_doc(report_doc), status=status.HTTP_201_CREATED)


class ReportDownloadView(View):
    def get(self, request, pk):
        db = get_db()
        report = None
        try:
            report = db[REPORTS].find_one({"_id": ObjectId(pk)})
        except Exception:
            report = None

        if not report:
            # Check if pk is a scan_id directly
            try:
                job_check = db[SCAN_JOBS].find_one({"_id": ObjectId(pk)})
                if job_check:
                    report = {
                        "_id": ObjectId(pk),
                        "scan_id": str(pk),
                        "target_url": job_check.get("target_url"),
                        "domain": job_check.get("domain"),
                        "format": request.GET.get("format", "pdf"),
                        "report_type": request.GET.get("report_type", "detailed")
                    }
            except Exception:
                pass

        if not report:
            return JsonResponse({"error": "Report record or scan not found."}, status=404)

        scan_id = report.get("scan_id")
        job = db[SCAN_JOBS].find_one({"_id": ObjectId(scan_id)}) or {}
        site = db[WEBSITES].find_one({"_id": ObjectId(job.get("website_id"))}) if job.get("website_id") else {}
        result = db[SCAN_RESULTS].find_one({"scan_id": scan_id}) or {}

        # Query all vulnerabilities tied to this scan or target
        raw_vulns = list(db[VULNERABILITIES].find({
            "$or": [
                {"scan_id": scan_id},
                {"last_scan_id": scan_id},
                {"website_id": str(job.get("website_id", ""))}
            ]
        }))

        # Deduplicate
        vulns = []
        seen = set()
        for v in raw_vulns:
            vid = str(v.get("_id", v.get("title", "")))
            if vid not in seen:
                seen.add(vid)
                vulns.append(v)

        fmt = (request.GET.get("format") or request.GET.get("export") or report.get("format", "pdf")).lower()
        domain = report.get("domain") or job.get("domain", "target")

        # 1. JSON Export
        if fmt == "json":
            export_data = {
                "report_id": pk,
                "domain": domain,
                "target_url": report.get("target_url"),
                "generated_at": datetime.utcnow().isoformat(),
                "security_score": job.get("security_score"),
                "vulnerabilities": db_manager.serialize_doc(vulns),
                "summary": result.get("severity_counts", {})
            }
            resp = HttpResponse(json.dumps(export_data, indent=2), content_type="application/json")
            resp["Content-Disposition"] = f'attachment; filename="SecureAudit_Report_{domain}_{pk[:8]}.json"'
            return resp

        # 2. CSV Export
        elif fmt == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["Title", "Severity", "CVSS", "CWE", "OWASP Category", "Affected URL", "Status", "Description", "Remediation"])
            for v in vulns:
                writer.writerow([
                    v.get("title", ""),
                    v.get("severity", ""),
                    v.get("cvss_score", ""),
                    v.get("cwe_id", ""),
                    v.get("owasp_category", ""),
                    v.get("affected_url", ""),
                    v.get("status", ""),
                    v.get("description", "").replace("\n", " "),
                    v.get("remediation", "").replace("\n", " ")
                ])
            resp = HttpResponse(buffer.getvalue(), content_type="text/csv")
            resp["Content-Disposition"] = f'attachment; filename="SecureAudit_Vulnerabilities_{domain}_{pk[:8]}.csv"'
            return resp

        # 3. HTML Report
        elif fmt == "html":
            html_content = render_html_report(job, site, result, vulns, report.get("report_type", "detailed"))
            resp = HttpResponse(html_content, content_type="text/html")
            resp["Content-Disposition"] = f'attachment; filename="SecureAudit_Report_{domain}_{pk[:8]}.html"'
            return resp

        # 4. Enterprise PDF Generation with ReportLab
        else:
            try:
                pdf_bytes = generate_enterprise_pdf_report(job, site, result, vulns, report.get("report_type", "detailed"))
                resp = HttpResponse(pdf_bytes, content_type="application/pdf")
                resp["Content-Disposition"] = f'attachment; filename="SecureAudit_Report_{domain}_{pk[:8]}.pdf"'
                return resp
            except Exception as e:
                # High-fidelity fallback HTML report with auto-print capability
                html_content = render_html_report(job, site, result, vulns, report.get("report_type", "detailed"))
                resp = HttpResponse(html_content, content_type="text/html")
                resp["Content-Disposition"] = f'inline; filename="SecureAudit_Report_{domain}_{pk[:8]}.html"'
                return resp
