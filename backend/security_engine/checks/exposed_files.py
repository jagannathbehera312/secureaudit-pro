"""
SecureAudit Pro - Safe Exposed Resource & Sensitive File Probe Module
Safely probes for exposed sensitive assets, environment configs, repository artifacts,
and backups without storing confidential content payloads.
Provides exhaustive technical descriptions and exact web server configuration snippets.
"""

from typing import List, Dict, Any
import requests
import urllib.parse

SAFE_PROBES = [
    {
        "path": "/.env",
        "title": "Exposed Environment Configuration File (.env)",
        "vuln_type": "exposed_env_file",
        "severity": "critical",
        "cvss_score": 9.8,
        "cwe_id": "CWE-552",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and ("DB_PASSWORD" in r.text or "SECRET_KEY" in r.text or "AWS_" in r.text or "DATABASE_URL" in r.text or "MONGO_URI" in r.text),
        "description": (
            "An environment configuration file (.env) is publicly accessible via direct HTTP GET requests. "
            "This file typically contains unencrypted production secrets, master database credentials, third-party API keys, and private signing keys."
        ),
        "impact": (
            "Immediate full system compromise. Adversaries can access production databases, compromise cloud infrastructure (AWS/GCP/Azure), "
            "and decrypt session data or forge authentication tokens."
        ),
        "remediation": (
            "1. In Nginx: Add a global block to deny access to all hidden dotfiles in /etc/nginx/nginx.conf:\n"
            "   location ~ /\\.(?!well-known).* {\n"
            "       deny all;\n"
            "       access_log off;\n"
            "       log_not_found off;\n"
            "   }\n"
            "2. In Apache: Add rule in .htaccess or httpd.conf:\n"
            "   <FilesMatch \"^\\.\">\n"
            "       Require all denied\n"
            "   </FilesMatch>\n"
            "3. Immediately rotate all credentials and API tokens stored in the compromised .env file.\n"
            "4. Remove .env from version control and ensure web root points only to public/ or dist/ directory."
        )
    },
    {
        "path": "/.git/HEAD",
        "title": "Exposed Git Source Control Repository (.git/HEAD)",
        "vuln_type": "exposed_git_repository",
        "severity": "critical",
        "cvss_score": 9.1,
        "cwe_id": "CWE-538",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and "ref: refs/" in r.text,
        "description": (
            "The .git source control metadata folder is publicly accessible over HTTP. "
            "Attackers can leverage tools like git-dumper to recursively reconstruct the entire application source code and commit history."
        ),
        "impact": (
            "Complete source code disclosure, exposure of internal architecture, and extraction of hardcoded credentials from previous git commits."
        ),
        "remediation": (
            "1. In Nginx: Block direct web access to .git:\n"
            "   location ~ /\\.git {\n"
            "       deny all;\n"
            "       return 404;\n"
            "   }\n"
            "2. In Apache: Add to .htaccess:\n"
            "   RedirectMatch 404 /\\.git\n"
            "3. Verification: curl -I https://yourdomain.com/.git/HEAD (Must return 403 Forbidden or 404 Not Found)."
        )
    },
    {
        "path": "/docker-compose.yml",
        "title": "Exposed Docker Compose Architecture Configuration (docker-compose.yml)",
        "vuln_type": "exposed_docker_compose",
        "severity": "high",
        "cvss_score": 8.2,
        "cwe_id": "CWE-200",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and ("version:" in r.text or "services:" in r.text) and ("image:" in r.text or "ports:" in r.text),
        "description": (
            "The docker-compose.yml infrastructure file is publicly exposed. It discloses container architecture, "
            "internal network mappings, service names, and environment variables."
        ),
        "impact": "Reveals internal service topologies, database configurations, and environment secrets.",
        "remediation": (
            "1. Remove docker-compose.yml from the public web server document root.\n"
            "2. Configure Nginx/Apache to forbid downloading .yml, .yaml, and config files from web roots."
        )
    },
    {
        "path": "/wp-config.php.bak",
        "title": "Exposed Database Backup Configuration (wp-config.php.bak)",
        "vuln_type": "exposed_config_backup",
        "severity": "high",
        "cvss_score": 8.6,
        "cwe_id": "CWE-530",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and ("DB_PASSWORD" in r.text or "DB_USER" in r.text),
        "description": "Backup text copy of server configuration file accessible directly without PHP execution.",
        "impact": "Direct database credential disclosure and database takeover.",
        "remediation": (
            "1. Delete all backup files (.bak, .old, .orig, .save, .swp) from production web roots.\n"
            "2. In Nginx, block access to backup extensions:\n"
            "   location ~* \\.(bak|old|orig|save|swp|temp)$ { deny all; }"
        )
    },
    {
        "path": "/server-status",
        "title": "Exposed Apache / Web Server Diagnostic Page (/server-status)",
        "vuln_type": "exposed_server_status",
        "severity": "medium",
        "cvss_score": 5.3,
        "cwe_id": "CWE-200",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and ("Apache Server Status" in r.text or "Current Time:" in r.text and "Server uptime:" in r.text),
        "description": "The web server status diagnostic page is publicly reachable without authentication.",
        "impact": "Discloses live client IP addresses, requested URLs, server worker status, and traffic load.",
        "remediation": (
            "1. In Apache: Restrict server-status access exclusively to localhost in /etc/apache2/mods-enabled/status.conf:\n"
            "   <Location /server-status>\n"
            "       SetHandler server-status\n"
            "       Require ip 127.0.0.1\n"
            "   </Location>"
        )
    },
    {
        "path": "/phpinfo.php",
        "title": "Exposed PHP Information Diagnostic File (phpinfo)",
        "vuln_type": "exposed_phpinfo",
        "severity": "medium",
        "cvss_score": 5.3,
        "cwe_id": "CWE-200",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and "PHP Version" in r.text and "Configuration" in r.text,
        "description": "A phpinfo() diagnostic script is publicly accessible.",
        "impact": "Reveals internal server directory paths, loaded modules, environment variables, and PHP configuration parameters.",
        "remediation": "Delete phpinfo scripts from all publicly reachable environments."
    },
    {
        "path": "/actuator/env",
        "title": "Exposed Spring Boot Actuator Environment Endpoint (/actuator/env)",
        "vuln_type": "exposed_actuator_env",
        "severity": "high",
        "cvss_score": 8.6,
        "cwe_id": "CWE-200",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and ("propertySources" in r.text or "activeProfiles" in r.text),
        "description": "The Spring Boot Actuator env endpoint is accessible without authentication.",
        "impact": "Exposes application configuration properties, environment variables, and potential database credentials.",
        "remediation": (
            "1. In application.properties: management.endpoints.web.exposure.exclude=env\n"
            "2. Secure actuator endpoints using Spring Security with HTTP Basic or OAuth2."
        )
    },
    {
        "path": "/swagger-ui.html",
        "title": "Exposed Interactive Swagger / OpenAPI Documentation (/swagger-ui.html)",
        "vuln_type": "exposed_api_docs",
        "severity": "low",
        "cvss_score": 3.7,
        "cwe_id": "CWE-200",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and ("swagger-ui" in r.text or "Swagger UI" in r.text),
        "description": "Interactive API documentation interface is exposed without authentication.",
        "impact": "Provides adversaries with an exhaustive map of all API routes, parameter names, schemas, and endpoints.",
        "remediation": "Require authentication to access Swagger UI in non-development environments."
    },
    {
        "path": "/package.json",
        "title": "Exposed Node.js Package Manifest (package.json)",
        "vuln_type": "exposed_package_json",
        "severity": "low",
        "cvss_score": 4.3,
        "cwe_id": "CWE-200",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and ("\"dependencies\"" in r.text and "\"name\"" in r.text),
        "description": "The package.json dependency file was served directly from the root.",
        "impact": "Discloses all backend and frontend NPM package names and exact versions, facilitating targeted CVE exploitation.",
        "remediation": "Do not expose project root as the web root. Serve exclusively from the dist/ or build/ folder."
    },
    {
        "path": "/.DS_Store",
        "title": "Exposed macOS Directory Metadata File (.DS_Store)",
        "vuln_type": "exposed_ds_store",
        "severity": "low",
        "cvss_score": 3.1,
        "cwe_id": "CWE-200",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and (b"\x00\x00\x00\x01Bud1" in r.content or "Bud1" in r.text),
        "description": "A .DS_Store file created by macOS Finder is accessible in the web root.",
        "impact": "Discloses directory filenames, unlinked hidden files, and internal directory structures.",
        "remediation": "Add .DS_Store to .gitignore and configure web server to deny access to all .DS_Store files."
    },
    {
        "path": "/robots.txt",
        "title": "Robots.txt Sensitive Disallow Path Disclosure",
        "vuln_type": "robots_sensitive_paths",
        "severity": "info",
        "cvss_score": 2.0,
        "cwe_id": "CWE-200",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 200 and any(p in r.text.lower() for p in ("/admin", "/secret", "/backup", "/private", "/internal")),
        "description": "The robots.txt file contains Disallow rules pointing to sensitive administrative or internal directories.",
        "impact": "Unintentionally reveals hidden directory names and administrative interfaces to attackers.",
        "remediation": "Enforce proper authentication and authorization controls on sensitive paths rather than relying on robots.txt obscurity."
    },
    {
        "path": "/.well-known/security.txt",
        "title": "Missing security.txt Responsible Disclosure Policy",
        "vuln_type": "missing_security_txt",
        "severity": "info",
        "cvss_score": 0.0,
        "cwe_id": "CWE-16",
        "owasp_category": "A02:2025 - Security Misconfiguration",
        "signature": lambda r: r.status_code == 404,
        "description": "The website does not publish a security.txt file (RFC 9116) to guide ethical security researchers.",
        "impact": "Legitimate security researchers may struggle to report discovered vulnerabilities securely.",
        "remediation": "Publish a security.txt file at /.well-known/security.txt with security contact details and PGP key."
    }
]


def check_exposed_resources(base_url: str, timeout: float = 4.0) -> List[Dict[str, Any]]:
    findings = []
    base_clean = base_url.rstrip("/")

    for probe in SAFE_PROBES:
        probe_url = f"{base_clean}{probe['path']}"
        try:
            resp = requests.get(
                probe_url,
                timeout=timeout,
                allow_redirects=False,
                verify=False,
                headers={"User-Agent": "SecureAudit-Pro-Scanner/2.0"}
            )
            
            if probe["signature"](resp):
                # Verify that 200 isn't just a generic SPA fallback serving index.html
                if probe["path"] != "/.well-known/security.txt" and "text/html" in resp.headers.get("Content-Type", ""):
                    if "<div id=\"root\"" in resp.text or "<div id=\"app\"" in resp.text:
                        continue  # Single-page app 200 catch-all; skip false positive

                evidence_snippet = resp.text[:120].replace("\n", " ").strip()
                findings.append({
                    "title": probe["title"],
                    "vuln_type": probe["vuln_type"],
                    "severity": probe["severity"],
                    "cvss_score": probe["cvss_score"],
                    "cwe_id": probe["cwe_id"],
                    "owasp_category": probe["owasp_category"],
                    "description": probe["description"],
                    "impact": probe["impact"],
                    "remediation": probe["remediation"],
                    "evidence": f"HTTP {resp.status_code} at {probe_url}. Content preview: {evidence_snippet}",
                    "affected_url": probe_url,
                    "confidence": "confirmed",
                    "status": "open"
                })
        except Exception:
            continue

    return findings
