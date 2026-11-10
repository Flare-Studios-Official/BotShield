"""Tests for SSRF prevention, IP validation, connection pinning, and response limits."""

import ipaddress
import socket
import pytest
import httpx
from unittest.mock import MagicMock, patch

from app.core.security import (
    ResponseSizeLimitExceeded,
    SSRFPinnedSyncBackend,
    SSRFValidationError,
    is_ip_private_or_reserved,
    sanitize_credentials,
    stream_safe_get,
    validate_and_resolve_url,
)


def test_private_and_loopback_ip_blocking():
    """Confirms RFC 1918, loopback, and metadata IPs are flagged."""
    test_cases = [
        ("127.0.0.1", True),
        ("10.0.0.1", True),
        ("192.168.1.100", True),
        ("172.16.0.50", True),
        ("169.254.169.254", True),
        ("0.0.0.0", True),
        ("::1", True),
        ("fe80::1", True),
        ("fc00::1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("93.184.216.34", False),
    ]
    for ip_str, should_block in test_cases:
        ip_obj = ipaddress.ip_address(ip_str)
        blocked, _reason = is_ip_private_or_reserved(ip_obj)
        assert blocked == should_block, f"Failed for {ip_str}: got blocked={blocked}, expected {should_block}"


def test_additional_disallowed_ranges():
    """Confirms CGNAT, TEST-NET, Class E, and IPv4-mapped IPv6 are strictly blocked."""
    disallowed_ips = [
        "100.64.0.1",            # Carrier-Grade NAT (RFC 6598)
        "100.127.255.254",       # CGNAT upper boundary
        "192.0.2.1",             # TEST-NET-1 (RFC 5737)
        "198.51.100.1",          # TEST-NET-2
        "203.0.113.1",           # TEST-NET-3
        "240.0.0.1",             # Class E / Reserved
        "0.0.0.1",               # 0.0.0.0/8
        "::ffff:127.0.0.1",      # IPv4-mapped loopback
        "::ffff:10.0.0.1",       # IPv4-mapped RFC 1918
        "::ffff:169.254.169.254",# IPv4-mapped cloud metadata
    ]
    for ip_str in disallowed_ips:
        ip_obj = ipaddress.ip_address(ip_str)
        blocked, reason = is_ip_private_or_reserved(ip_obj)
        assert blocked is True, f"Expected {ip_str} to be blocked ({reason})"


def test_disallowed_schemes():
    """Ensures file://, ftp://, and gopher:// schemes are rejected."""
    for bad_url in ["ftp://example.com", "file:///etc/passwd", "gopher://evil.com"]:
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url(bad_url)


def test_localhost_hostname_blocking():
    """Ensures localhost names and cloud metadata domains are blocked without DNS resolution."""
    blocked_hosts = [
        "http://localhost",
        "https://localhost:8080",
        "http://localhost.localdomain",
        "http://metadata.google.internal",
        "http://metadata.gcp.internal",
        "http://instance-data",
    ]
    for host in blocked_hosts:
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url(host)


def test_blocked_ports():
    """Ensures internal service ports (SSH, MySQL, Redis, Docker) are rejected."""
    for port in [22, 3306, 6379, 27017, 2375, 2376]:
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url(f"https://example.com:{port}")


def test_credential_sanitization():
    """Verifies passwords and API tokens are redacted."""
    raw = "http://admin:SuperSecret123@proxy.example.com:8080"
    scrubbed = sanitize_credentials(raw)
    assert "SuperSecret123" not in scrubbed
    assert "admin:***@" in scrubbed

    bearer = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token"
    scrubbed_b = sanitize_credentials(bearer)
    assert "Bearer [REDACTED]" in scrubbed_b


def test_connection_level_ip_pinning():
    """Ensures SSRFPinnedSyncBackend connects to the pinned IP and intercepts unpinned destinations."""
    pinned_map = {"example.com": "93.184.216.34"}
    backend = SSRFPinnedSyncBackend(pinned_hosts=pinned_map, allow_private=False)

    # Mock socket.create_connection to capture target IP
    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock(spec=socket.socket)
        mock_conn.return_value = mock_sock

        stream = backend.connect_tcp(host="example.com", port=443)
        assert stream is not None
        mock_conn.assert_called_once()
        args, _kwargs = mock_conn.call_args
        target_addr = args[0]
        # Must connect to the pinned IP 93.184.216.34, NOT resolve hostname
        assert target_addr == ("93.184.216.34", 443)


def test_ip_pinning_blocks_private_dns_rebinding():
    """Ensures backend refuses connection if a host rebinds or attempts private IP destination."""
    backend = SSRFPinnedSyncBackend(pinned_hosts={}, allow_private=False)

    # If DNS returns a private IP at connection time, must raise SSRFValidationError
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
        ]
        with pytest.raises(SSRFValidationError):
            backend.connect_tcp(host="rebound-host.com", port=80)


def test_streaming_body_size_limit_content_length():
    """stream_safe_get aborts immediately when Content-Length exceeds limit."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.headers = {"content-length": "10485760"}  # 10 MB

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.stream.return_value.__enter__.return_value = mock_resp

    with pytest.raises(ResponseSizeLimitExceeded) as exc_info:
        stream_safe_get(
            client=mock_client,
            url="https://example.com/huge.bin",
            max_bytes=1024 * 1024,  # 1 MB limit
        )
    assert "exceeds maximum limit" in str(exc_info.value)


def test_streaming_body_size_limit_chunked():
    """stream_safe_get terminates stream and raises when chunked stream exceeds limit."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.headers = {}  # No Content-Length
    # Stream returns chunks of 8KB, total 24KB
    mock_resp.iter_bytes.return_value = [b"A" * 8192, b"B" * 8192, b"C" * 8192]

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.stream.return_value.__enter__.return_value = mock_resp

    # Set limit to 10KB (exceeded on second chunk)
    with pytest.raises(ResponseSizeLimitExceeded) as exc_info:
        stream_safe_get(
            client=mock_client,
            url="https://example.com/stream",
            max_bytes=10 * 1024,
        )
    assert "exceeded maximum allowed limit" in str(exc_info.value)
