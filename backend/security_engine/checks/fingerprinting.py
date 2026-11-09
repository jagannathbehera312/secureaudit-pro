"""
SecureAudit Pro - Technology Fingerprinting & Asset Inventory Module
Identifies web servers, frameworks, programming languages, CMS, CDNs, and libraries.
"""

import re
from typing import Dict, Any, List

TECH_SIGNATURES = [
    # Web Servers
    {"name": "Nginx", "category": "Web Server", "headers": {"server": r"nginx(?:/([\d.]+))?"}},
    {"name": "Apache HTTP Server", "category": "Web Server", "headers": {"server": r"apache(?:/([\d.]+))?"}},
    {"name": "Microsoft IIS", "category": "Web Server", "headers": {"server": r"microsoft-iis(?:/([\d.]+))?"}},
    {"name": "Caddy", "category": "Web Server", "headers": {"server": r"caddy"}},
    {"name": "LiteSpeed", "category": "Web Server", "headers": {"server": r"litespeed"}},

    # Cloud & CDN
    {"name": "Cloudflare", "category": "CDN / WAF", "headers": {"server": r"cloudflare", "cf-ray": r".*"}},
    {"name": "AWS CloudFront", "category": "CDN", "headers": {"x-amz-cf-id": r".*", "server": r"cloudfront"}},
    {"name": "Fastly", "category": "CDN", "headers": {"x-fastly-request-id": r".*"}},
    {"name": "Akamai", "category": "CDN", "headers": {"x-akamai-transformed": r".*"}},
    {"name": "Vercel", "category": "PaaS / Hosting", "headers": {"x-vercel-id": r".*"}},
    {"name": "Netlify", "category": "PaaS / Hosting", "headers": {"x-nf-request-id": r".*"}},

    # Backend Frameworks & Runtimes
    {"name": "Django", "category": "Web Framework", "headers": {"x-frame-options": r"SAMEORIGIN"}, "cookies": [r"csrftoken", r"sessionid"]},
    {"name": "Laravel", "category": "Web Framework", "cookies": [r"laravel_session", r"XSRF-TOKEN"]},
    {"name": "Express.js", "category": "Web Framework", "headers": {"x-powered-by": r"Express"}},
    {"name": "Next.js", "category": "Web Framework", "headers": {"x-powered-by": r"Next\.js"}, "html": [r"/_next/static/"]},
    {"name": "Ruby on Rails", "category": "Web Framework", "headers": {"x-powered-by": r"Phusion Passenger"}, "cookies": [r"_session_id"]},
    {"name": "ASP.NET", "category": "Web Framework", "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r".*"}, "cookies": [r"ASP\.NET_SessionId"]},
    {"name": "Spring Boot", "category": "Web Framework", "headers": {"x-application-context": r".*"}, "cookies": [r"JSESSIONID"]},
    {"name": "PHP", "category": "Language", "headers": {"x-powered-by": r"php(?:/([\d.]+))?"}, "cookies": [r"PHPSESSID"]},

    # CMS
    {"name": "WordPress", "category": "CMS", "html": [r"/wp-content/", r"/wp-includes/"], "headers": {"link": r"wp-json"}},
    {"name": "Drupal", "category": "CMS", "headers": {"x-generator": r"Drupal(?: ([0-9]+))?"}, "html": [r"Drupal\.settings"]},
    {"name": "Joomla", "category": "CMS", "headers": {"x-content-encoded-by": r"Joomla"}},

    # Frontend Frameworks
    {"name": "React", "category": "Frontend Framework", "html": [r"data-reactroot", r"_reactListening", r"react\.production\.min\.js"]},
    {"name": "Vue.js", "category": "Frontend Framework", "html": [r"data-v-[a-f0-9]+", r"vue\.runtime\.min\.js", r"v-cloak"]},
    {"name": "Angular", "category": "Frontend Framework", "html": [r"ng-version=", r"ng-app="]},
    {"name": "Tailwind CSS", "category": "CSS Framework", "html": [r"class=\"[^\"]*(?:flex|grid|hidden|bg-|text-|p-|m-)[^\"]*\""]},
    {"name": "Bootstrap", "category": "CSS Framework", "html": [r"bootstrap(?:\.min)?\.css", r"bootstrap(?:\.min)?\.js"]},
    {"name": "jQuery", "category": "JavaScript Library", "html": [r"jquery(?:-([0-9.]+))?(?:\.min)?\.js"]}
]


def fingerprint_technologies(headers: Dict[str, str], html_body: str = "", cookies: List[str] = None) -> List[Dict[str, Any]]:
    detected = []
    norm_headers = {k.lower(): v for k, v in headers.items()}
    cookie_str = " ".join(cookies or [])

    for tech in TECH_SIGNATURES:
        match_version = None
        matched = False

        # Header checks
        if "headers" in tech:
            for h_key, h_pattern in tech["headers"].items():
                val = norm_headers.get(h_key.lower())
                if val:
                    m = re.search(h_pattern, val, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            match_version = m.group(1)
                        break

        # Cookie checks
        if not matched and "cookies" in tech:
            for c_pat in tech["cookies"]:
                if re.search(c_pat, cookie_str, re.IGNORECASE):
                    matched = True
                    break

        # HTML checks
        if not matched and html_body and "html" in tech:
            for h_pat in tech["html"]:
                m = re.search(h_pat, html_body, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        match_version = m.group(1)
                    break

        if matched:
            detected.append({
                "name": tech["name"],
                "category": tech["category"],
                "version": match_version or "Detected"
            })

    return detected
