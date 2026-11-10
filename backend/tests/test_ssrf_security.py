"""Tests for SSRF prevention, IP validation, and credential redaction."""

import pytest
from app.core.security import (
    SSRFValidationError,
    is_ip_private_or_reserved,
    sanitize_credentials,
    validate_and_resolve_url,
)
import ipaddress


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
        blocked, reason = is_ip_private_or_reserved(ip_obj)
        assert blocked == should_block, f"Failed for {ip_str}: got blocked={blocked}, expected {should_block}"


def test_disallowed_schemes():
    """Ensures file://, ftp://, and gopher:// schemes are rejected."""
    for bad_url in ["ftp://example.com", "file:///etc/passwd", "gopher://evil.com"]:
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url(bad_url)


def test_localhost_hostname_blocking():
    """Ensures localhost names are blocked without DNS resolution."""
    for host in ["http://localhost", "https://localhost:8080", "http://localhost.localdomain"]:
        with pytest.raises(SSRFValidationError):
            validate_and_resolve_url(host)


def test_blocked_ports():
    """Ensures internal service ports (SSH, MySQL, Redis) are rejected."""
    for port in [22, 3306, 6379, 27017, 2375]:
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
