"""
SecureAudit Pro - OWASP API Security Top 10 Assessment Module
Audits REST / GraphQL endpoints for API inventory, pagination limits, and schema disclosure.
"""

from typing import List, Dict, Any
import requests
import json
import urllib.parse


def check_owasp_api_security(target_url: str, timeout: float = 4.0) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")

    # 1. API Inventory & Exposed OpenAPI / Swagger Schemas (API9:2023 Improper Inventory Management)
    schema_paths = [
        "/api/schema/",
        "/api/v1/swagger.json",
        "/api/docs/",
        "/openapi.json",
        "/v2/api-docs",
        "/v3/api-docs"
    ]
    for sp in schema_paths:
        try:
            r = requests.get(f"{base_clean}{sp}", timeout=timeout, verify=False)
            if r.status_code == 200 and ("openapi" in r.text.lower() or "swagger" in r.text.lower() or "paths" in r.text.lower()):
                findings.append({
                    "title": f"Unauthenticated OpenAPI / Swagger Schema Exposure ({sp})",
                    "vuln_type": "api_schema_exposure",
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "cwe_id": "CWE-200",
                    "owasp_category": "API9:2023 - Improper Inventory Management",
                    "description": f"The full machine-readable API specification is publicly reachable at {sp} without authentication.",
                    "impact": "Enables attackers to map private endpoints, internal parameter names, and undocumented API methods.",
                    "remediation": "Restrict API documentation and schema endpoints behind authenticated analyst roles.",
                    "evidence": f"GET {base_clean}{sp} returned valid API schema (HTTP 200).",
                    "affected_url": f"{base_clean}{sp}",
                    "confidence": "confirmed",
                    "status": "open"
                })
                break
        except Exception:
            pass

    # 2. GraphQL Introspection Query Check (API8:2023 Security Misconfiguration)
    graphql_paths = ["/graphql", "/api/graphql"]
    introspection_query = {"query": "{ __schema { types { name } } }"}
    for gp in graphql_paths:
        try:
            gr = requests.post(
                f"{base_clean}{gp}",
                json=introspection_query,
                timeout=timeout,
                verify=False,
                headers={"Content-Type": "application/json"}
            )
            if gr.status_code == 200 and "__schema" in gr.text:
                findings.append({
                    "title": f"GraphQL Introspection Enabled at {gp}",
                    "vuln_type": "graphql_introspection_enabled",
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "cwe_id": "CWE-200",
                    "owasp_category": "API8:2023 - Security Misconfiguration",
                    "description": f"GraphQL endpoint at {gp} accepts introspection queries from unauthenticated clients.",
                    "impact": "Allows attackers to query and reconstruct the entire backend GraphQL data schema, query types, mutations, and fields.",
                    "remediation": "Disable introspection in production environments.",
                    "evidence": f"POST to {base_clean}{gp} returned __schema data.",
                    "affected_url": f"{base_clean}{gp}",
                    "confidence": "confirmed",
                    "status": "open"
                })
                break
        except Exception:
            pass

    # 3. Unrestricted Resource Consumption (API4:2023 Unrestricted Resource Consumption)
    # Check if API allows arbitrarily large pagination limits (e.g. limit=100000)
    for api_probe in ["/api/v1/items?limit=100000", "/api/users?limit=99999"]:
        try:
            r = requests.get(f"{base_clean}{api_probe}", timeout=timeout, verify=False)
            if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 500:
                findings.append({
                    "title": "Unrestricted API Resource Consumption / Excessive Pagination Limit",
                    "vuln_type": "api_excessive_data_allocation",
                    "severity": "medium",
                    "cvss_score": 6.5,
                    "cwe_id": "CWE-770",
                    "owasp_category": "API4:2023 - Unrestricted Resource Consumption",
                    "description": "The API endpoint permits oversized limit query parameters without enforcing a safe server-side cap.",
                    "impact": "Can lead to database saturation, heavy memory consumption, and API denial-of-service.",
                    "remediation": "Enforce a maximum page size (e.g. max 100 items per request) on all paginated collections.",
                    "evidence": f"Request {api_probe} returned more than 500 records.",
                    "affected_url": f"{base_clean}{api_probe}",
                    "confidence": "confirmed",
                    "status": "open"
                })
                break
        except Exception:
            pass

    return findings
