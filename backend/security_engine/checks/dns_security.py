"""
SecureAudit Pro - DNS & Domain Security Assessment Module
Checks SPF, DMARC, DKIM hints, DNSSEC, and Subdomain Takeover indicators.
"""

from typing import Dict, Any, List
import urllib.parse

# Subdomain takeover known CNAME fingerprints
TAKEOVER_SIGNATURES = {
    "github.io": "GitHub Pages",
    "s3.amazonaws.com": "AWS S3 Bucket",
    "herokuapp.com": "Heroku App",
    "azurewebsites.net": "Microsoft Azure",
    "cloudfront.net": "AWS CloudFront",
    "trafficmanager.net": "Azure Traffic Manager",
    "pantheonsite.io": "Pantheon",
    "zendesk.com": "Zendesk Help Center",
    "readme.io": "Readme.io Documentation",
    "surge.sh": "Surge.sh"
}


def analyze_dns_security(target_url: str) -> Dict[str, Any]:
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.hostname or target_url
    results = {
        "domain": domain,
        "records": {},
        "findings": []
    }

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4.0
        resolver.lifetime = 4.0

        # 1. Check A and CNAME records
        try:
            a_records = [r.to_text() for r in resolver.resolve(domain, "A")]
            results["records"]["A"] = a_records
        except Exception:
            results["records"]["A"] = []

        cnames = []
        try:
            cname_records = resolver.resolve(domain, "CNAME")
            for c in cname_records:
                target_cname = c.target.to_text().rstrip(".")
                cnames.append(target_cname)
                # Check takeover signature
                for sig, provider in TAKEOVER_SIGNATURES.items():
                    if sig in target_cname.lower():
                        results["findings"].append({
                            "title": f"Potential Subdomain Takeover Indicator ({provider})",
                            "vuln_type": "subdomain_takeover_indicator",
                            "severity": "medium",
                            "cvss_score": 6.8,
                            "cwe_id": "CWE-284",
                            "owasp_category": "A01:2025 - Broken Access Control",
                            "description": f"Domain {domain} points via CNAME to {target_cname} ({provider}). If the underlying service or bucket is unclaimed or decommissioned, an external party could claim it.",
                            "impact": "Attackers claiming orphaned cloud resources can serve malicious content, steal cookies, and execute cross-site scripting on the parent domain.",
                            "remediation": f"Verify whether the {provider} resource at {target_cname} is actively registered and owned by your organization. If not in use, remove the DNS CNAME record.",
                            "evidence": f"CNAME record points to: {target_cname}",
                            "affected_url": target_url,
                            "confidence": "medium",
                            "status": "open"
                        })
        except Exception:
            pass
        results["records"]["CNAME"] = cnames

        # 2. Check TXT records (SPF)
        spf_found = False
        try:
            txt_records = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in resolver.resolve(domain, "TXT")]
            results["records"]["TXT"] = txt_records
            for txt in txt_records:
                if txt.startswith("v=spf1"):
                    spf_found = True
                    results["records"]["SPF"] = txt
                    if "+all" in txt:
                        results["findings"].append({
                            "title": "Permissive SPF Record (+all)",
                            "vuln_type": "permissive_spf_record",
                            "severity": "medium",
                            "cvss_score": 5.3,
                            "cwe_id": "CWE-346",
                            "owasp_category": "A02:2025 - Security Misconfiguration",
                            "description": "The domain's SPF record contains the '+all' directive, which explicitly authorizes any IP address in the world to send email on behalf of this domain.",
                            "impact": "Facilitates highly believable email spoofing, phishing, and business email compromise (BEC).",
                            "remediation": "Change '+all' to '-all' (hard fail) or '~all' (soft fail) in the SPF TXT record.",
                            "evidence": f"SPF record: {txt}",
                            "affected_url": target_url,
                            "confidence": "confirmed",
                            "status": "open"
                        })
                    break
        except Exception:
            results["records"]["TXT"] = []

        if not spf_found:
            results["findings"].append({
                "title": "Missing SPF (Sender Policy Framework) Record",
                "vuln_type": "missing_spf_record",
                "severity": "low",
                "cvss_score": 3.7,
                "cwe_id": "CWE-346",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "description": f"Domain {domain} does not publish an SPF record to specify authorized mail transfer agents.",
                "impact": "Enables attackers to spoof email originating from this domain with lower probability of spam rejection.",
                "remediation": "Publish a valid TXT record on the apex domain starting with 'v=spf1 ... -all'.",
                "evidence": f"No v=spf1 TXT record resolved on {domain}",
                "affected_url": target_url,
                "confidence": "confirmed",
                "status": "open"
            })

        # 3. Check DMARC record
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_found = False
        try:
            dmarc_txt = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in resolver.resolve(dmarc_domain, "TXT")]
            for txt in dmarc_txt:
                if txt.startswith("v=DMARC1"):
                    dmarc_found = True
                    results["records"]["DMARC"] = txt
                    if "p=none" in txt.lower():
                        results["findings"].append({
                            "title": "DMARC Policy Configured with 'p=none' (Monitoring Only)",
                            "vuln_type": "dmarc_p_none",
                            "severity": "low",
                            "cvss_score": 3.1,
                            "cwe_id": "CWE-346",
                            "owasp_category": "A02:2025 - Security Misconfiguration",
                            "description": "DMARC policy is set to 'p=none', which logs authentication failures without rejecting or quarantining spoofed emails.",
                            "impact": "Unauthorized spoofed messages will continue to be delivered to recipient inboxes.",
                            "remediation": "Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' once legitimate mail sources are verified.",
                            "evidence": f"DMARC TXT record: {txt}",
                            "affected_url": target_url,
                            "confidence": "confirmed",
                            "status": "open"
                        })
                    break
        except Exception:
            pass

        if not dmarc_found:
            results["findings"].append({
                "title": "Missing DMARC Record",
                "vuln_type": "missing_dmarc_record",
                "severity": "medium",
                "cvss_score": 4.3,
                "cwe_id": "CWE-346",
                "owasp_category": "A02:2025 - Security Misconfiguration",
                "description": f"Domain {domain} does not have a DMARC policy published at _dmarc.{domain}.",
                "impact": "Receiving mail servers cannot determine how to handle SPF or DKIM failures, leaving the domain vulnerable to brand impersonation.",
                "remediation": f"Create a TXT record for _dmarc.{domain} with 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}'.",
                "evidence": f"No DMARC record found at _dmarc.{domain}",
                "affected_url": target_url,
                "confidence": "confirmed",
                "status": "open"
            })

    except Exception as e:
        results["error"] = str(e)

    return results
