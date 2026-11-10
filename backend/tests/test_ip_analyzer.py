"""Tests for IP analysis, IPv4/IPv6 classification, RDAP discovery, and reputation."""

import pytest
from unittest.mock import patch

from app.services.ip_analyzer import analyze_ip_address
from app.services.reputation_service import check_tor_exit_node


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


def test_unverified_public_ip_never_labeled_malicious():
    """Defensive standard: a public IP without verified abuse evidence is never marked malicious."""
    with patch("app.services.ip_analyzer.query_rdap") as mock_rdap:
        mock_rdap.return_value = {
            "network_name": "TEST-NET",
            "network_handle": "NET-1",
            "registered_org": "Example Internet Provider",
            "country": "US",
            "rir_source": "ARIN RDAP",
        }
        res = analyze_ip_address("8.8.8.8", db=None)
        assert res.is_routable is True
        assert res.threat_level == "low"
        assert res.reputation_score <= 10
        # Confirms an unverified public IP is never flagged as malicious
        assert res.reputation_score < 25


def test_rdap_registration_vs_asn_distinction():
    """IP RDAP returns network registration data, not BGP ASN routing data."""
    with patch("app.services.ip_analyzer.query_rdap") as mock_rdap, \
         patch("app.services.ip_analyzer.check_ipinfo") as mock_ipinfo:
        mock_rdap.return_value = {
            "network_name": "GOGL",
            "network_handle": "NET-8-8-8-0-1",
            "registered_org": "Google LLC",
            "country": "US",
            "rir_source": "ARIN RDAP",
        }
        mock_ipinfo.return_value = None
        res = analyze_ip_address("8.8.8.8", db=None)
        # ASN field must clarify that IP RDAP does not provide BGP AS numbers
        assert "Not resolved via IP RDAP" in res.asn
        assert res.as_org == "Google LLC"


def test_asn_resolved_when_external_provider_available():
    """When an external routing provider is queried, real BGP ASN is populated."""
    with patch("app.services.ip_analyzer.query_rdap") as mock_rdap, \
         patch("app.services.ip_analyzer.check_ipinfo") as mock_ipinfo:
        mock_rdap.return_value = {
            "network_name": "GOGL",
            "network_handle": "NET-8-8-8-0-1",
            "registered_org": "Google LLC",
            "country": "US",
            "rir_source": "ARIN RDAP",
        }
        mock_ipinfo.return_value = {
            "org": "AS15169 Google LLC",
            "city": "Mountain View",
            "country": "US",
            "is_hosting": True,
        }
        res = analyze_ip_address("8.8.8.8", db=None)
        assert res.asn == "AS15169"
        assert res.as_org == "Google LLC"


def test_tor_exit_live_and_fallback():
    """Tor exit evaluation distinguishes confirmed matches, confirmed non-matches, and unverified fallback."""
    # Scenario A: Live Tor set available and IP is present
    with patch("app.services.reputation_service.get_live_tor_exit_set") as mock_tor:
        mock_tor.return_value = {"51.15.43.205", "185.220.101.4"}
        is_tor, conf, _src = check_tor_exit_node("51.15.43.205")
        assert is_tor is True
        assert conf == "confirmed"

        # IP not present in directory
        is_tor_2, conf_2, _src_2 = check_tor_exit_node("8.8.8.8")
        assert is_tor_2 is False
        assert conf_2 == "confirmed"

    # Scenario B: Tor Project directory unreachable (fallback)
    with patch("app.services.reputation_service.get_live_tor_exit_set") as mock_tor_down:
        mock_tor_down.return_value = None
        is_tor_3, conf_3, src_3 = check_tor_exit_node("1.2.3.4")
        assert is_tor_3 is False
        assert conf_3 == "unverified"
        assert "Unavailable" in src_3
