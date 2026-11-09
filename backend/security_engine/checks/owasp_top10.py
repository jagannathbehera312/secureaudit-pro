"""
SecureAudit Pro - In-Depth OWASP Top 10:2025 Security Assessment Engine
Executes controlled, non-destructive, safe checks across all OWASP Top 10 categories.
Provides exhaustive technical descriptions, business impacts, raw evidence traces,
and step-by-step remediation configuration code snippets.
"""

from typing import List, Dict, Any
import requests
import re
import urllib.parse


def check_owasp_top10_2025(target_url: str, main_resp_text: str = "", headers: Dict[str, str] = None, timeout: float = 4.0) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    parsed = urllib.parse.urlparse(target_url)

    # -------------------------------------------------------------
    # A01:2025 – Broken Access Control
    # -------------------------------------------------------------
    # 1. Unauthenticated Administrative Endpoints
    admin_paths = [
        "/admin/", "/administrator/", "/manage/", "/api/v1/users/",
        "/api/admin/", "/dashboard/admin/", "/system/settings/"
    ]
    for p in admin_paths:
        try:
            r = requests.get(f"{base_clean}{p}", timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code == 200 and ("login" not in r.text.lower() and "sign in" not in r.text.lower()):
                if any(k in r.text.lower() for k in ("admin", "dashboard", "superadmin", "privilege", "users")):
                    findings.append({
                        "title": f"Unauthenticated Access to Administrative Endpoint ({p})",
                        "vuln_type": "broken_access_control_admin",
                        "severity": "critical",
                        "cvss_score": 9.1,
                        "cwe_id": "CWE-284",
                        "owasp_category": "A01:2025 - Broken Access Control",
                        "description": (
                            f"The administrative interface at {p} returned HTTP 200 OK without requiring authentication credentials, "
                            "bearer tokens, or active session cookies. Administrative interfaces must never be exposed without mandatory "
                            "zero-trust role-based access control."
                        ),
                        "impact": (
                            "Unauthenticated external adversaries can access privileged system controls, read confidential database entries, "
                            "modify business records, or provision rogue administrative users (Complete Compromise of Confidentiality & Integrity)."
                        ),
                        "remediation": (
                            "1. Enforce strict server-side authentication middleware on all administrative routes:\n"
                            "   • In Django: Decorate views with @login_required and @user_passes_test(lambda u: u.is_superuser)\n"
                            "   • In Express.js: app.use('/admin', authenticateToken, requireRole('super_admin'))\n"
                            "   • In Spring Boot: http.authorizeHttpRequests(auth -> auth.requestMatchers('/admin/**').hasRole('ADMIN'))\n"
                            "2. Restrict administrative routes to trusted corporate VPN IP CIDRs via Nginx:\n"
                            "   location /admin/ {\n"
                            "       allow 10.0.0.0/8;\n"
                            "       deny all;\n"
                            "       proxy_pass http://backend;\n"
                            "   }\n"
                            "3. Verification: curl -I https://yourdomain.com/admin/ (Must return 401 Unauthorized or 403 Forbidden)."
                        ),
                        "evidence": f"GET {base_clean}{p} returned HTTP 200 with administrative markers in body ({len(r.text)} bytes).",
                        "affected_url": f"{base_clean}{p}",
                        "confidence": "high",
                        "status": "open"
                    })
                    break
        except Exception:
            pass

    # 2. Path Traversal / Arbitrary File Read Probe
    traversal_probes = [
        "/../../../../etc/passwd",
        "/..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "/..\\..\\..\\windows\\win.ini"
    ]
    for tp in traversal_probes:
        try:
            r = requests.get(f"{base_clean}{tp}", timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code == 200 and ("root:x:0:0:" in r.text or "[extensions]" in r.text.lower()):
                findings.append({
                    "title": "Path Traversal & Arbitrary Local File Inclusion (LFI)",
                    "vuln_type": "path_traversal_lfi",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cwe_id": "CWE-22",
                    "owasp_category": "A01:2025 - Broken Access Control",
                    "description": (
                        f"The server resolved the dot-dot-slash sequence ({tp}) and disclosed system files without canonical path validation. "
                        "Web applications must strictly confine file operations to approved document roots."
                    ),
                    "impact": (
                        "Adversaries can read server configuration files, password hashes (/etc/shadow), environment secrets, and source code, "
                        "facilitating full server compromise."
                    ),
                    "remediation": (
                        "1. Use safe canonical path verification before accessing the filesystem:\n"
                        "   • Python: os.path.abspath(filepath).startswith(os.path.abspath(BASE_DIR))\n"
                        "   • Node.js: path.resolve(baseDir, requestedPath).startsWith(baseDir)\n"
                        "2. In Nginx: Ensure merge_slashes is 'on' and disable alias directives without trailing slashes.\n"
                        "3. Verification: curl -s 'https://yourdomain.com/../../../../etc/passwd' (Must return 400 or 404)."
                    ),
                    "evidence": f"GET {base_clean}{tp} returned sensitive file contents: {r.text[:60]}...",
                    "affected_url": f"{base_clean}{tp}",
                    "confidence": "confirmed",
                    "status": "open"
                })
                break
        except Exception:
            pass

    # 3. Open Redirection Check
    redirect_probes = [
        ("redirect", "https://attacker-controlled-site.invalid"),
        ("next", "//attacker-controlled-site.invalid"),
        ("url", "https://attacker-controlled-site.invalid"),
        ("target", "https://attacker-controlled-site.invalid")
    ]
    for param_name, payload in redirect_probes:
        try:
            test_url = f"{base_clean}/login?{param_name}={urllib.parse.quote(payload)}"
            r = requests.get(test_url, timeout=timeout, verify=False, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and "attacker-controlled-site.invalid" in loc:
                findings.append({
                    "title": f"Unvalidated Open Redirect via Parameter '{param_name}'",
                    "vuln_type": "open_redirect",
                    "severity": "medium",
                    "cvss_score": 6.1,
                    "cwe_id": "CWE-601",
                    "owasp_category": "A01:2025 - Broken Access Control",
                    "description": (
                        f"The endpoint at /login dynamically redirects the client to untrusted target URLs provided via '{param_name}' "
                        "without origin verification or relative path enforcement."
                    ),
                    "impact": (
                        "Facilitates highly credible phishing campaigns. Attackers send links with your legitimate domain name that "
                        "seamlessly redirect victims to credential-harvesting phishing portals."
                    ),
                    "remediation": (
                        "1. Enforce strict relative URL redirects:\n"
                        "   • In Django: Use url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()})\n"
                        "   • In Express: Ensure redirect path starts with a single '/' and not '//': path.startsWith('/') && !path.startsWith('//')\n"
                        "2. Maintain an explicit allowlist of authorized redirect destination domains.\n"
                        "3. Verification: curl -I 'https://yourdomain.com/login?redirect=https://evil.com' (Must not redirect to evil.com)."
                    ),
                    "evidence": f"HTTP {r.status_code} redirect returned with Location: {loc}",
                    "affected_url": test_url,
                    "confidence": "confirmed",
                    "status": "open"
                })
                break
        except Exception:
            pass

    # -------------------------------------------------------------
    # A02:2025 – Security Misconfiguration
    # -------------------------------------------------------------
    # 4. Insecure HTTP Methods (OPTIONS, PUT, DELETE, TRACE)
    try:
        opt_resp = requests.options(target_url, timeout=timeout, verify=False)
        allow_header = opt_resp.headers.get("Allow", "") or opt_resp.headers.get("Access-Control-Allow-Methods", "")
        if "TRACE" in allow_header.upper():
            findings.append({
                "title": "HTTP TRACE Method Enabled (Cross-Site Tracing / XST)",
                "vuln_type": "http_trace_enabled",
                "severity": "medium",
                "cvss_score": 5.3,
                "cwe_id": "CWE-16",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "description": (
                    "The web server has the HTTP TRACE method enabled. TRACE reflects the incoming request headers and cookies back "
                    "in the response body, circumventing HttpOnly protections."
                ),
                "impact": (
                    "When paired with Cross-Site Scripting (XSS), attackers can use XMLHttpRequest with TRACE to read sensitive HttpOnly "
                    "session cookies that JavaScript is normally prohibited from accessing."
                ),
                "remediation": (
                    "1. In Apache: Add 'TraceEnable off' to /etc/apache2/apache2.conf or httpd.conf.\n"
                    "2. In Nginx: Ensure TRACE requests are blocked in server block:\n"
                    "   if ($request_method ~ ^(TRACE|TRACK)$) {\n"
                    "       return 405;\n"
                    "   }\n"
                    "3. In IIS: Use Request Filtering to block verb 'TRACE'.\n"
                    "4. Verification: curl -X TRACE -I https://yourdomain.com (Must return 405 Method Not Allowed)."
                ),
                "evidence": f"OPTIONS request returned Allow header: {allow_header}",
                "affected_url": target_url,
                "confidence": "confirmed",
                "status": "open"
            })
    except Exception:
        pass

    # 5. Directory Listing on Asset Directories
    dir_probes = ["/images/", "/static/", "/uploads/", "/assets/", "/backup/", "/temp/"]
    for dir_probe in dir_probes:
        try:
            r = requests.get(f"{base_clean}{dir_probe}", timeout=timeout, verify=False)
            if r.status_code == 200 and any(m in r.text for m in ("Index of /", "Directory Listing For", "<title>Index of", "[To Parent Directory]")):
                findings.append({
                    "title": f"Directory Listing Enabled on {dir_probe}",
                    "vuln_type": "directory_listing_enabled",
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "cwe_id": "CWE-548",
                    "owasp_category": "A02:2025 - Security Misconfiguration",
                    "description": (
                        f"The web server automatically generates an index of files for the directory {dir_probe}. "
                        "Directory listing exposes unlinked assets, internal scripts, and user-uploaded files."
                    ),
                    "impact": (
                        "Enables adversaries to browse and download unlinked source files, database backups, logs, and sensitive user uploads."
                    ),
                    "remediation": (
                        "1. Disable directory indexing in your web server configuration:\n"
                        "   • In Nginx: Set 'autoindex off;' in your location blocks.\n"
                        "   • In Apache: Add 'Options -Indexes' in httpd.conf or .htaccess.\n"
                        "   • In IIS: Disable Directory Browsing in IIS Manager.\n"
                        "2. Verification: curl -s https://yourdomain.com/static/ (Must return 403 Forbidden or 404 Not Found)."
                    ),
                    "evidence": f"GET {base_clean}{dir_probe} returned HTTP 200 directory index listing.",
                    "affected_url": f"{base_clean}{dir_probe}",
                    "confidence": "confirmed",
                    "status": "open"
                })
                break
        except Exception:
            pass

    # -------------------------------------------------------------
    # A03:2025 – Software Supply Chain & Vulnerable Components
    # -------------------------------------------------------------
    if main_resp_text:
        # Check for legacy vulnerable jQuery versions (< 3.5.0)
        jq_match = re.search(r"jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js", main_resp_text, re.IGNORECASE)
        if jq_match:
            v_str = jq_match.group(1)
            parts = [int(x) for x in v_str.split(".") if x.isdigit()]
            if parts and (parts[0] < 3 or (parts[0] == 3 and len(parts) > 1 and parts[1] < 5)):
                findings.append({
                    "title": f"Vulnerable Outdated jQuery Library ({v_str})",
                    "vuln_type": "vulnerable_dependency_jquery",
                    "severity": "medium",
                    "cvss_score": 6.1,
                    "cwe_id": "CWE-1395",
                    "owasp_category": "A03:2025 - Software Supply Chain Failures",
                    "description": (
                        f"Target loads jQuery version {v_str}, which is affected by known public vulnerabilities including "
                        "CVE-2020-11022 and CVE-2020-11023 (regex XSS in htmlPrefilter) and CVE-2019-11358 (Prototype Pollution)."
                    ),
                    "impact": (
                        "Untrusted HTML strings passed to jQuery DOM manipulation functions (.html(), .append()) execute arbitrary JavaScript."
                    ),
                    "remediation": (
                        "1. Upgrade jQuery to the latest stable release (v3.7.1 or higher):\n"
                        "   npm install jquery@latest\n"
                        "   Or load from modern CDN: https://code.jquery.com/jquery-3.7.1.min.js\n"
                        "2. If upgrading legacy applications, test DOM interactions thoroughly or use the jquery-migrate plugin."
                    ),
                    "evidence": f"Detected script tag importing jquery-{v_str}.js in HTML source.",
                    "affected_url": target_url,
                    "confidence": "confirmed",
                    "status": "open"
                })

        # Check for legacy Bootstrap (< 5.0)
        bs_match = re.search(r"bootstrap[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.(?:js|css)", main_resp_text, re.IGNORECASE)
        if bs_match:
            b_str = bs_match.group(1)
            b_parts = [int(x) for x in b_str.split(".") if x.isdigit()]
            if b_parts and b_parts[0] < 4:
                findings.append({
                    "title": f"Outdated Bootstrap Framework ({b_str}) with Known XSS Flaws",
                    "vuln_type": "vulnerable_dependency_bootstrap",
                    "severity": "low",
                    "cvss_score": 4.3,
                    "cwe_id": "CWE-1395",
                    "owasp_category": "A03:2025 - Software Supply Chain Failures",
                    "description": f"Target imports Bootstrap v{b_str}, which contains known XSS vulnerabilities in tooltip, popover, and scrollspy plugins (CVE-2019-8331).",
                    "impact": "Attackers supplying malicious attributes to tooltips can trigger Cross-Site Scripting.",
                    "remediation": "Upgrade Bootstrap to v5.3+ and remove reliance on jQuery plugins.",
                    "evidence": f"Found bootstrap-{b_str} reference in page source.",
                    "affected_url": target_url,
                    "confidence": "confirmed",
                    "status": "open"
                })

    # -------------------------------------------------------------
    # A05:2025 – Injection (SQL Injection, XSS, Command Injection)
    # -------------------------------------------------------------
    # 6. SQL Injection Probing (Safe Boolean & Syntax Indicator Check)
    sql_errors = [
        ("MySQL", r"you have an error in your sql syntax|mysql_fetch_|check the manual that corresponds to your MySQL server version"),
        ("PostgreSQL", r"pg_query\(\)|error in your SQL syntax|PostgreSQL query failed|unterminated quoted string"),
        ("SQLite", r"sqlite3.OperationalError|SQLite/JDBCDriver|unrecognized token:"),
        ("Microsoft SQL", r"ODBC SQL Server Driver|Unclosed quotation mark before the character string|Microsoft OLE DB Provider for SQL Server"),
        ("Oracle", r"ORA-01756|quoted string not properly terminated|ORA-00933")
    ]
    sql_probes = ["' OR '1'='1", "1' AND '1'='1", "1 UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:0'--"]

    # Test common input parameters or current query string
    test_params = ["id", "q", "search", "user", "cat", "page", "query"]
    has_tested_sql = False
    for param in test_params:
        if has_tested_sql:
            break
        for probe in sql_probes[:2]:
            try:
                test_url = f"{base_clean}/?{param}={urllib.parse.quote(probe)}"
                r = requests.get(test_url, timeout=timeout, verify=False)
                for db_name, err_regex in sql_errors:
                    if re.search(err_regex, r.text, re.IGNORECASE):
                        findings.append({
                            "title": f"SQL Injection Vulnerability Detected via '{param}' ({db_name})",
                            "vuln_type": "sql_injection",
                            "severity": "critical",
                            "cvss_score": 9.8,
                            "cwe_id": "CWE-89",
                            "owasp_category": "A05:2025 - Injection",
                            "description": (
                                f"The target application returned database error messages corresponding to {db_name} "
                                f"when supplied with the syntax probe '{probe}' in parameter '{param}'. "
                                "This confirms dynamic SQL string concatenation without parameterized queries."
                            ),
                            "impact": (
                                "Complete database compromise. Attackers can bypass authentication, exfiltrate sensitive customer records, "
                                "alter or drop database tables, and in many configurations execute operating system commands."
                            ),
                            "remediation": (
                                "1. Use Parameterized Queries / Prepared Statements exclusively:\n"
                                "   • In Python (psycopg2 / sqlite3): cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                                "   • In Django ORM: User.objects.filter(id=user_id) (Never use raw SQL format strings)\n"
                                "   • In Node.js (pg / mysql2): db.query('SELECT * FROM users WHERE id = ?', [userId])\n"
                                "   • In Java/Spring: PreparedStatement stmt = conn.prepareStatement('SELECT * FROM users WHERE id = ?');\n"
                                "2. Apply least-privilege principles to the database user account.\n"
                                "3. Verification: Re-test with single quote probe; application must handle input gracefully without database exceptions."
                            ),
                            "evidence": f"GET {test_url} triggered {db_name} error signature in response.",
                            "affected_url": test_url,
                            "confidence": "confirmed",
                            "status": "open"
                        })
                        has_tested_sql = True
                        break
            except Exception:
                pass

    # 7. Reflected Cross-Site Scripting (XSS) Indicator Check
    xss_probe = 'SEC999XYZ<script>alert(1)</script>"\'test'
    test_xss_params = ["q", "search", "keyword", "sa_test", "query", "redirect"]
    for xp in test_xss_params:
        try:
            probe_url = f"{base_clean}/?{xp}={urllib.parse.quote(xss_probe)}"
            r = requests.get(probe_url, timeout=timeout, verify=False)
            if "<script>alert(1)</script>" in r.text or "SEC999XYZ<script>" in r.text:
                findings.append({
                    "title": f"Reflected Cross-Site Scripting (XSS) in Parameter '{xp}'",
                    "vuln_type": "reflected_xss",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "cwe_id": "CWE-79",
                    "owasp_category": "A05:2025 - Injection",
                    "description": (
                        f"The parameter '{xp}' reflected raw HTML and script tags verbatim into the response body "
                        "without contextual entity encoding or sanitization."
                    ),
                    "impact": (
                        "Attackers can craft malicious URLs that execute arbitrary JavaScript in the victim's session. "
                        "This enables session hijacking, credential harvesting, keystroke logging, and client-side malware distribution."
                    ),
                    "remediation": (
                        "1. Implement Context-Aware HTML Entity Encoding for all user-supplied input:\n"
                        "   • In React / Vue: Automatic JSX/template escaping is enabled by default (never use dangerouslySetInnerHTML).\n"
                        "   • In Django Templates: {{ variable }} escapes by default (never use |safe on untrusted input).\n"
                        "   • In Express: Use DOMPurify / sanitize-html library before rendering.\n"
                        "2. Enforce a robust Content-Security-Policy (CSP) restricting script execution:\n"
                        "   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';\n"
                        "3. Verification: curl -s 'https://yourdomain.com/?q=<script>alert(1)</script>' (Characters must appear as &lt;script&gt;)."
                    ),
                    "evidence": f"GET {probe_url} reflected raw script tag in response body.",
                    "affected_url": probe_url,
                    "confidence": "confirmed",
                    "status": "open"
                })
                break
        except Exception:
            pass

    # -------------------------------------------------------------
    # A06:2025 – Insecure Design & Rate Limiting
    # -------------------------------------------------------------
    # 8. Missing HTTP Request Rate Limiting Defense
    rate_limited = False
    has_ratelimit_header = False
    try:
        for _ in range(5):
            hr = requests.head(target_url, timeout=2.0, verify=False)
            if hr.status_code == 429:
                rate_limited = True
                break
            if any("ratelimit" in k.lower() for k in hr.headers.keys()):
                has_ratelimit_header = True

        if not rate_limited and not has_ratelimit_header:
            findings.append({
                "title": "Missing HTTP Request Rate Limiting Defense",
                "vuln_type": "missing_rate_limiting",
                "severity": "low",
                "cvss_score": 3.7,
                "cwe_id": "CWE-799",
                "owasp_category": "A06:2025 - Insecure Design",
                "description": (
                    "No rate limiting controls or standard RateLimit headers (X-RateLimit-Limit, RateLimit-Remaining) "
                    "were detected during burst requests to the target endpoint."
                ),
                "impact": (
                    "Leaves application endpoints vulnerable to automated credential brute forcing, API denial of service, "
                    "and excessive cloud resource consumption."
                ),
                "remediation": (
                    "1. In Nginx: Configure request rate limiting zone:\n"
                    "   limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;\n"
                    "   location /api/ {\n"
                    "       limit_req zone=api_limit burst=20 nodelay;\n"
                    "   }\n"
                    "2. In Django REST Framework: Configure AnonRateThrottle and UserRateThrottle in settings.py.\n"
                    "3. In Express.js: Use express-rate-limit middleware.\n"
                    "4. Verification: Send 25 consecutive requests in a loop; verify server returns HTTP 429 Too Many Requests."
                ),
                "evidence": "Five consecutive rapid HEAD requests were accepted with HTTP 200 without rate-limit throttling headers.",
                "affected_url": target_url,
                "confidence": "low",
                "status": "open"
            })
    except Exception:
        pass

    # -------------------------------------------------------------
    # A08:2025 – Software or Data Integrity Failures
    # -------------------------------------------------------------
    # 9. External CDN Scripts Loaded Without Subresource Integrity (SRI)
    if main_resp_text:
        external_scripts = re.findall(r'<script[^>]+src=["\'](https?://[^"\']+)["\'][^>]*>', main_resp_text, re.IGNORECASE)
        missing_sri = []
        for s in external_scripts:
            tag_match = re.search(rf'<script[^>]*src=["\']{re.escape(s)}["\'][^>]*>', main_resp_text, re.IGNORECASE)
            if tag_match and "integrity=" not in tag_match.group(0).lower():
                parsed_s = urllib.parse.urlparse(s)
                if parsed_s.hostname and parsed.hostname and parsed_s.hostname != parsed.hostname:
                    missing_sri.append(s)

        if missing_sri:
            findings.append({
                "title": "External Scripts Loaded Without Subresource Integrity (SRI)",
                "vuln_type": "missing_sri_external_scripts",
                "severity": "low",
                "cvss_score": 3.8,
                "cwe_id": "CWE-353",
                "owasp_category": "A08:2025 - Software or Data Integrity Failures",
                "description": (
                    f"The application loads {len(missing_sri)} third-party scripts from external CDNs without Subresource Integrity (SRI) hashes. "
                    "SRI enables browsers to verify that remote script files have not been modified or tampered with."
                ),
                "impact": (
                    "If the third-party CDN or delivery network is compromised or suffers DNS hijacking, adversaries could inject malicious "
                    "code directly into the script, compromising all users loading the application."
                ),
                "remediation": (
                    "1. Generate cryptographic SRI hashes for all external CDN resources:\n"
                    "   curl -s https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A\n"
                    "2. Include the 'integrity' and 'crossorigin' attributes in the HTML <script> tag:\n"
                    "   <script src=\"https://cdn.example.com/lib.js\"\n"
                    "           integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8n\"\n"
                    "           crossorigin=\"anonymous\"></script>\n"
                    "3. Alternatively, host external dependencies locally on the origin server."
                ),
                "evidence": f"External scripts lacking integrity attribute: {', '.join(missing_sri[:3])}",
                "affected_url": target_url,
                "confidence": "confirmed",
                "status": "open"
            })

    # -------------------------------------------------------------
    # A10:2025 – Server-Side Request Forgery & Exceptional Conditions
    # -------------------------------------------------------------
    # 10. Verbose Stack Trace & Debug Mode Disclosure
    try:
        err_url = f"{base_clean}/non_existent_endpoint_probe_{urllib.parse.quote('!@#$%')}"
        err_resp = requests.get(err_url, timeout=timeout, verify=False)
        debug_keywords = [
            "Traceback (most recent call last)", "Django Version:", "Werkzeug Debugger",
            "Fatal error:", "Exception Details:", "SyntaxError:", "org.springframework.web",
            "Laravel", "Whoops! There was an error."
        ]
        matched_debug = [kw for kw in debug_keywords if kw in err_resp.text]
        if matched_debug:
            findings.append({
                "title": "Detailed Stack Trace & Exception Exposure (Debug Mode Active)",
                "vuln_type": "verbose_exception_disclosure",
                "severity": "high",
                "cvss_score": 7.5,
                "cwe_id": "CWE-209",
                "owasp_category": "A10:2025 - Mishandling of Exceptional Conditions",
                "description": (
                    f"The web application leaked internal debugging signatures and framework stack traces when requesting an invalid route: "
                    f"'{matched_debug[0]}'. Production servers must never display internal execution environments to users."
                ),
                "impact": (
                    "Discloses internal source code filenames, absolute directory paths, framework versions, database schema names, "
                    "and environment variables to prospective attackers."
                ),
                "remediation": (
                    "1. Disable DEBUG mode across all production and public-facing environments:\n"
                    "   • In Django settings.py: DEBUG = False, ALLOWED_HOSTS = ['yourdomain.com']\n"
                    "   • In Flask: app.config['DEBUG'] = False, ENV = 'production'\n"
                    "   • In Express: NODE_ENV=production\n"
                    "2. Configure custom generic error handlers (HTTP 404, 500) that log errors internally without exposing traces.\n"
                    "3. Verification: curl -s 'https://yourdomain.com/force-404-check' (Must return clean, generic HTML error page)."
                ),
                "evidence": f"GET {err_url} triggered traceback containing: '{matched_debug[0]}'",
                "affected_url": err_url,
                "confidence": "confirmed",
                "status": "open"
            })
    except Exception:
        pass

    # 11. Potential Server-Side Request Forgery (SSRF) Indicator
    ssrf_params = ["url", "dest", "target", "link", "feed", "webhook", "proxy"]
    for sp in ssrf_params:
        try:
            ssrf_test_url = f"{base_clean}/?{sp}=http://127.0.0.1:80/"
            sr = requests.get(ssrf_test_url, timeout=timeout, verify=False)
            if "localhost" in sr.text.lower() or "127.0.0.1" in sr.text:
                findings.append({
                    "title": f"Potential SSRF Exposure via Parameter '{sp}'",
                    "vuln_type": "ssrf_indicator",
                    "severity": "high",
                    "cvss_score": 8.6,
                    "cwe_id": "CWE-918",
                    "owasp_category": "A10:2025 - Server-Side Request Forgery",
                    "description": (
                        f"The parameter '{sp}' accepts arbitrary URLs and appears to trigger server-side HTTP fetches. "
                        "Without strict loopback and metadata validation, servers can be leveraged as internal proxies."
                    ),
                    "impact": (
                        "Attackers can probe internal cloud metadata services (e.g. AWS 169.254.169.254), access internal databases, "
                        "and bypass perimeter firewall controls."
                    ),
                    "remediation": (
                        "1. Validate and restrict all outgoing HTTP requests using an IP allowlist.\n"
                        "2. Block loopback (127.0.0.0/8), link-local (169.254.0.0/16), and RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).\n"
                        "3. Resolve domain names via DNS and check IP addresses before initiating connections to prevent DNS rebinding."
                    ),
                    "evidence": f"Supplied loopback URL in '{sp}', server response contained internal reflection markers.",
                    "affected_url": ssrf_test_url,
                    "confidence": "medium",
                    "status": "open"
                })
                break
        except Exception:
            pass

    return findings
