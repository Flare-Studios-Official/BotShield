"""Tests for IP analysis, IPv4/IPv6 classification, and reputation."""

import pytest
from app.services.ip_analyzer import analyze_ip_address


def test_private_ip_local_analysis():
    """Private IP is identified and processed locally without external queries."""
    res = analyze_ip_address("192.168.1.1", db=None)
    assert res.is_routable is False
    assert res.classification == "private"
    assert res.reputation_score == 0
    assert res.threat_level == "low"
    assert "Private" in res.as_org


def test_loopback_ipv6_analysis():
    """IPv6 loopback is identified properly."""
    res = analyze_ip_address("::1", db=None)
    assert res.is_routable is False
    assert res.classification == "loopback"
    assert res.ip_version == 6


def test_invalid_ip_format():
    """Malformed strings trigger ValueError."""
    with pytest.raises(ValueError):
        analyze_ip_address("999.999.999.999", db=None)
    with pytest.raises(ValueError):
        analyze_ip_address("not-an-ip", db=None)
