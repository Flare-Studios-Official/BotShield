"""BotShield Security Core Module

Provides enterprise SSRF defense, IP address classification, DNS re-validation,
connection-level IP pinning, streaming response-body limits, credential redaction,
and administrative API authorization.
"""

import hmac
import ipaddress
import logging
import re
import socket
import typing
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpcore
from httpcore._backends.sync import SyncBackend, SyncStream
from httpcore._exceptions import (
    ConnectError,
    ConnectTimeout,
    ExceptionMapping,
    map_exceptions,
)
import httpx
from fastapi import Header, HTTPException, status

from app.config import settings

logger = logging.getLogger("botshield.security")

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


class ResponseSizeLimitExceeded(ValueError):
    """Raised when an outbound HTTP response body exceeds configured size limits."""
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
        # 0.0.0.0/8 current network
        if ip in ipaddress.IPv4Network("0.0.0.0/8"):
            return True, "Broadcast / This-Network address block (0.0.0.0/8)"

        # Carrier Grade NAT: 100.64.0.0/10
        cgnat = ipaddress.IPv4Network("100.64.0.0/10")
        if ip in cgnat:
            return True, "Shared / Carrier-Grade NAT address space (RFC 6598)"

        # Documentation blocks (TEST-NET)
        for doc_net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
            if ip in ipaddress.IPv4Network(doc_net):
                return True, "Test / Documentation network (TEST-NET)"

        # 240.0.0.0/4 Class E / Reserved
        if ip in ipaddress.IPv4Network("240.0.0.0/4"):
            return True, "Class E / Reserved address block (240.0.0.0/4)"

    return False, "Public routable address"


def validate_and_resolve_url(
    url: str,
    allow_private: bool = False,
    allow_custom_ports: bool = False,
) -> Tuple[str, str, int, str]:
    """Validates a target URL against SSRF rules and resolves DNS safely.

    Returns:
        (clean_url, primary_raw_ip, port, hostname)
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


class SSRFPinnedSyncBackend(SyncBackend):
    """Custom httpcore NetworkBackend that pins outbound TCP connections to validated IPs.

    Guarantees that the exact IP validated by SSRF controls is used for the TCP connection,
    completely preventing DNS rebinding and Time-Of-Check / Time-Of-Use (TOCTOU) attacks,
    while preserving TLS SNI and server certificate validation against the original hostname.
    """

    def __init__(self, pinned_hosts: Dict[str, str], allow_private: bool = False):
        super().__init__()
        self.pinned_hosts = {k.lower(): v for k, v in pinned_hosts.items()}
        self.allow_private = allow_private

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[Any] | None = None,
    ) -> SyncStream:
        host_lower = host.lower()
        if host_lower in self.pinned_hosts:
            target_ip = self.pinned_hosts[host_lower]
        else:
            # Inline defensive validation if host was not pre-pinned
            _, target_ip, _, _ = validate_and_resolve_url(
                f"http://{host}:{port}",
                allow_private=self.allow_private,
                allow_custom_ports=True,
            )
            self.pinned_hosts[host_lower] = target_ip

        # Re-verify destination IP directly before socket creation
        if not self.allow_private:
            ip_obj = ipaddress.ip_address(target_ip)
            disallowed, reason = is_ip_private_or_reserved(ip_obj)
            if disallowed:
                raise SSRFValidationError(
                    f"Connection blocked: Destination IP {target_ip} is disallowed ({reason})."
                )

        address = (target_ip, port)
        source_address = None if local_address is None else (local_address, 0)
        exc_map: ExceptionMapping = {
            socket.timeout: ConnectTimeout,
            OSError: ConnectError,
        }
        if socket_options is None:
            socket_options = []

        with map_exceptions(exc_map):
            sock = socket.create_connection(
                address,
                timeout,
                source_address=source_address,
            )
            for option in socket_options:
                sock.setsockopt(*option)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        return SyncStream(sock)


class SSRFPinnedTransport(httpx.HTTPTransport):
    """HTTPX Transport backed by SSRFPinnedSyncBackend to pin verified destination IPs."""

    def __init__(self, pinned_hosts: Dict[str, str], allow_private: bool = False, **kwargs):
        super().__init__(**kwargs)
        backend = SSRFPinnedSyncBackend(pinned_hosts=pinned_hosts, allow_private=allow_private)
        self._pool = httpcore.ConnectionPool(
            ssl_context=self._pool._ssl_context,
            network_backend=backend,
            http1=True,
            http2=False,
            retries=0,
        )


def create_pinned_client(
    pinned_hosts: Dict[str, str],
    allow_private: bool = False,
    timeout: float = 8.0,
) -> httpx.Client:
    """Creates an httpx.Client with IP pinning enabled for the specified hosts."""
    transport = SSRFPinnedTransport(pinned_hosts=pinned_hosts, allow_private=allow_private)
    return httpx.Client(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,  # Redirects must be traversed manually to re-verify IPs
    )


def stream_safe_get(
    client: httpx.Client,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    max_bytes: int = 2 * 1024 * 1024,
    timeout: Optional[float] = None,
) -> Tuple[httpx.Response, bytes]:
    """Performs an HTTP GET request with streaming enforcement of maximum response size.

    Immediately terminates the download if Content-Length or streamed chunks exceed max_bytes.
    Returns:
        (response_metadata, response_content_bytes)
    Raises:
        ResponseSizeLimitExceeded if response size limit is breached.
        httpx.HTTPError on network failures.
    """
    req_headers = dict(headers) if headers else {}

    with client.stream("GET", url, headers=req_headers, timeout=timeout) as resp:
        # Pre-check Content-Length header if present
        cl_header = resp.headers.get("content-length")
        if cl_header and cl_header.strip().isdigit():
            cl_val = int(cl_header.strip())
            if cl_val > max_bytes:
                raise ResponseSizeLimitExceeded(
                    f"Response Content-Length ({cl_val} bytes) exceeds maximum limit ({max_bytes} bytes)."
                )

        chunks: List[bytes] = []
        total_downloaded = 0
        for chunk in resp.iter_bytes(chunk_size=16384):
            total_downloaded += len(chunk)
            if total_downloaded > max_bytes:
                raise ResponseSizeLimitExceeded(
                    f"Response body exceeded maximum allowed limit ({max_bytes} bytes). Transfer aborted."
                )
            chunks.append(chunk)

        body_bytes = b"".join(chunks)
        # Populate response _content so caller can use resp.text / resp.json() normally
        resp._content = body_bytes
        return resp, body_bytes


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


def require_admin_auth(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> bool:
    """FastAPI security dependency protecting administrative configuration and review endpoints.

    In production environments, rejects access with 403 Forbidden if no admin API key is configured.
    When configured, verifies the presented key using constant-time comparison.
    """
    configured_key = settings.admin_api_key.strip()

    if configured_key:
        token = x_api_key
        if not token and authorization:
            if authorization.startswith("Bearer "):
                token = authorization[7:].strip()
            else:
                token = authorization.strip()

        if not token or not hmac.compare_digest(token, configured_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing administrative API key.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return True

    # When deployed in production without an admin key configured, fail closed
    if settings.environment.lower() == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative endpoints are disabled in production until BOTSHIELD_ADMIN_API_KEY is configured.",
        )

    # In development mode with no key set, log warning and permit local access
    logger.debug("Administrative endpoint accessed without BOTSHIELD_ADMIN_API_KEY (development mode).")
    return True
