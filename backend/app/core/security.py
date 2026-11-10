"""BotShield Security Core Module

Provides SSRF defense, IP address classification, DNS re-validation,
credential redaction, and safe outbound connection validation.
"""

import ipaddress
import re
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse

# Restricted / Dangerous ports commonly used for internal services
BLOCKED_PORTS = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    110,   # POP3
    135,   # RPC
    139,   # NetBIOS
    143,   # IMAP
    445,   # SMB
    1433,  # MSSQL
    1521,  # Oracle
    2375,  # Docker unauthenticated
    2376,  # Docker TLS
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # Alternate HTTP (often internal proxies/admin)
    8443,  # Alternate HTTPS
    9200,  # Elasticsearch
    11211, # Memcached
    27017, # MongoDB
}

# Cloud metadata addresses
CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS / Azure / GCP metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
}

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.gcp.internal",
    "instance-data",
}


class SSRFValidationError(ValueError):
    """Raised when an outbound URL fails defensive SSRF validation."""
    pass


def is_ip_private_or_reserved(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Inspects an IP address and determines if it is private, reserved, loopback, or cloud metadata.

    Returns:
        (is_disallowed, reason_description)
    """
    str_ip = str(ip)

    # Cloud metadata check
    if str_ip in CLOUD_METADATA_IPS:
        return True, "Cloud provider instance metadata address (169.254.169.254)"

    # Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_ip_private_or_reserved(ip.ipv4_mapped)

    if ip.is_loopback:
        return True, "Loopback / Localhost address range"

    if ip.is_private:
        return True, "RFC 1918 / Private network address range"

    if ip.is_link_local:
        return True, "Link-local address range"

    if ip.is_multicast:
        return True, "Multicast address range"

    if ip.is_reserved:
        return True, "IETF Reserved address range"

    if ip.is_unspecified:
        return True, "Unspecified address (0.0.0.0 / ::)"

    # Specific IPv4 checks
    if isinstance(ip, ipaddress.IPv4Address):
        # Carrier Grade NAT: 100.64.0.0/10
        cgnat = ipaddress.IPv4Network("100.64.0.0/10")
        if ip in cgnat:
            return True, "Shared / Carrier-Grade NAT address space (RFC 6598)"

        # Documentation blocks (TEST-NET)
        for doc_net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
            if ip in ipaddress.IPv4Network(doc_net):
                return True, "Test / Documentation network (TEST-NET)"

    return False, "Public routable address"


def validate_and_resolve_url(
    url: str,
    allow_private: bool = False,
    allow_custom_ports: bool = False
) -> Tuple[str, str, int, str]:
    """Validates a target URL against SSRF rules and resolves DNS safely.

    Returns:
        (clean_url, resolved_ip, port, hostname)
    Raises:
        SSRFValidationError on any violation.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("URL parameter is missing or invalid.")

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise SSRFValidationError(f"Disallowed protocol scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("Target URL must specify a valid hostname.")

    hostname_lower = hostname.lower()

    # Reject cloud metadata hostnames
    if hostname_lower in CLOUD_METADATA_HOSTS or hostname_lower.endswith(".internal"):
        raise SSRFValidationError(f"Target hostname '{hostname}' resolves to a cloud metadata / internal service.")

    # Reject localhost keywords
    if hostname_lower in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        raise SSRFValidationError("Loopback target 'localhost' is strictly prohibited.")

    # Determine port
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    if not allow_custom_ports and port not in (80, 443):
        if port in BLOCKED_PORTS:
            raise SSRFValidationError(f"Port {port} is restricted to prevent lateral internal service access.")
        # Non-standard ports warning or rejection
        if port < 80 or port > 65535:
            raise SSRFValidationError(f"Invalid TCP port {port}.")

    # DNS Resolution & Verification
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFValidationError(f"DNS resolution failed for '{hostname}': {e}")

    if not addr_info:
        raise SSRFValidationError(f"No address records found for hostname '{hostname}'.")

    # Check ALL resolved IP addresses for SSRF violations
    resolved_ips = []
    for entry in addr_info:
        sockaddr = entry[4]
        raw_ip = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
            resolved_ips.append((raw_ip, ip_obj))
        except ValueError:
            continue

    if not resolved_ips:
        raise SSRFValidationError(f"Could not parse resolved IP records for '{hostname}'.")

    primary_raw_ip, primary_ip_obj = resolved_ips[0]

    if not allow_private:
        for raw_ip, ip_obj in resolved_ips:
            disallowed, reason = is_ip_private_or_reserved(ip_obj)
            if disallowed:
                raise SSRFValidationError(
                    f"Destination hostname '{hostname}' resolved to disallowed address {raw_ip}: {reason}."
                )

    clean_url = parsed.geturl()
    return clean_url, primary_raw_ip, port, hostname


def sanitize_credentials(text: str) -> str:
    """Redacts passwords, tokens, and basic auth credentials from URLs and strings."""
    if not text:
        return ""
    # Redact user:pass@host in URLs
    redacted = re.sub(r"://([^:@\s]+):([^@\s]+)@", r"://\1:***@", text)
    # Redact Authorization: Bearer xxx
    redacted = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED]", redacted, flags=re.IGNORECASE)
    # Redact common key patterns
    redacted = re.sub(r"(api[_-]?key[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted
