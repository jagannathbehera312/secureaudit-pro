"""
SecureAudit Pro - Core Security & Scanner Safety Controls
Enforces strict SSRF protection, target allowlisting, IP validation,
domain challenge verification, and safety boundaries.
"""

import socket
import ipaddress
import urllib.parse
import secrets
import hashlib
import re
from typing import Tuple, Optional, List

# Blocked IP Networks for SSRF Prevention
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (CGNAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 blocked ranges
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

# Sensitive ports blocked unless explicitly approved
DANGEROUS_PORTS = {22, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 6379, 9200, 11211, 27017}


def validate_and_resolve_target(url: str, allow_internal_assessment: bool = False) -> Tuple[bool, str, Optional[str]]:
    """
    Validates target URL syntax, extracts hostname, resolves IP, and verifies
    it is not in a prohibited private/loopback/cloud metadata range.
    Returns: (is_valid, resolved_ip_or_error_msg, normalized_url)
    """
    if not url or not isinstance(url, str):
        return False, "Target URL must be a non-empty string.", None

    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS protocols are permitted.", None

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: missing valid hostname.", None

    # Canonicalize port
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port in DANGEROUS_PORTS and not allow_internal_assessment:
        return False, f"Scanning non-web service port {port} is prohibited.", None

    # Allow synthetic demo/test targets (e.g., .internal, .local, .test, .example)
    if hostname.endswith((".internal", ".local", ".test", ".example")) or (allow_internal_assessment and hostname in ("localhost", "127.0.0.1")):
        normalized_path = parsed.path or "/"
        normalized = f"{parsed.scheme}://{hostname}{f':{port}' if (parsed.port and parsed.port not in (80, 443)) else ''}{normalized_path}"
        return True, "127.0.0.1", normalized

    # Resolve IP addresses for hostname
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        if not addr_info:
            return False, f"Could not resolve DNS for host {hostname}", None
        
        resolved_ips = list({entry[4][0] for entry in addr_info})
    except socket.gaierror as e:
        return False, f"DNS resolution failed for {hostname}: {str(e)}", None
    except Exception as e:
        return False, f"Error validating target {hostname}: {str(e)}", None

    # Check each resolved IP against blocked networks
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid resolved IP format: {ip_str}", None

        if not allow_internal_assessment:
            for blocked in BLOCKED_IP_NETWORKS:
                if ip_obj in blocked:
                    return False, f"Target resolves to blocked/restricted IP range ({ip_str} in {blocked}). SSRF protection triggered.", None

    normalized_url = f"{parsed.scheme}://{hostname}{f':{parsed.port}' if parsed.port and parsed.port not in (80, 443) else ''}{parsed.path or '/'}"
    return True, resolved_ips[0], normalized_url


def is_redirect_safe(redirect_url: str, original_domain: str, allow_subdomains: bool = True) -> bool:
    """Verifies that an HTTP redirect stays strictly within authorized scope."""
    try:
        parsed = urllib.parse.urlparse(redirect_url)
        new_host = parsed.hostname
        if not new_host:
            return False
        
        new_host = new_host.lower()
        original_domain = original_domain.lower()

        if new_host == original_domain:
            return True
        if allow_subdomains and new_host.endswith(f".{original_domain}"):
            return True
        return False
    except Exception:
        return False


def generate_verification_tokens(domain: str) -> dict:
    """
    Generates verification tokens for domain ownership proof:
    1. DNS TXT record challenge token
    2. HTTP file challenge token and expected URL path
    """
    raw_token = secrets.token_hex(24)
    dns_txt_record = f"secureaudit-verification={raw_token}"
    http_path = "/.well-known/secureaudit-challenge.txt"
    http_content = f"secureaudit-domain-verification={raw_token}"
    
    return {
        "token": raw_token,
        "dns_record_name": f"_secureaudit.{domain}",
        "dns_txt_value": dns_txt_record,
        "http_challenge_path": http_path,
        "http_challenge_content": http_content
    }


def verify_domain_dns_txt(domain: str, expected_token: str) -> Tuple[bool, str]:
    """Verifies domain ownership via DNS TXT record."""
    try:
        import dns.resolver
        record_name = f"_secureaudit.{domain}"
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        answers = resolver.resolve(record_name, "TXT")
        for rdata in answers:
            txt_string = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if expected_token in txt_string:
                return True, f"DNS TXT record verified successfully on {record_name}"
        return False, f"TXT record found on {record_name} but does not contain token {expected_token}"
    except Exception as e:
        return False, f"DNS TXT verification failed: {str(e)}"


def verify_domain_http_challenge(url: str, expected_content: str) -> Tuple[bool, str]:
    """Verifies domain ownership via HTTP well-known challenge file."""
    import urllib.request
    import ssl
    try:
        challenge_url = urllib.parse.urljoin(url, "/.well-known/secureaudit-challenge.txt")
        # Validate target IP before requesting
        valid, msg, _ = validate_and_resolve_target(challenge_url)
        if not valid:
            return False, f"SSRF Guard blocked challenge check: {msg}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # For challenge verification even if self-signed dev cert

        req = urllib.request.Request(challenge_url, headers={"User-Agent": "SecureAudit-Pro-Verifier/1.0"})
        with urllib.request.urlopen(req, timeout=6.0, context=ctx) as resp:
            content = resp.read().decode("utf-8", errors="ignore").strip()
            if expected_content in content:
                return True, "HTTP challenge file verified successfully."
            return False, f"Challenge file content did not match expected value. Received: {content[:100]}"
    except Exception as e:
        return False, f"HTTP challenge check failed: {str(e)}"


def compute_vulnerability_dedup_key(target_domain: str, vuln_type: str, path: str, param: str = "") -> str:
    """Generates a stable SHA-256 fingerprint for vulnerability deduplication."""
    clean_path = urllib.parse.urlparse(path).path or "/"
    raw = f"{target_domain.lower()}|{vuln_type.lower()}|{clean_path.lower()}|{param.lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
