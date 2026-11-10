"""BotShield IP Intelligence Analyzer Service

Performs standards-compliant IP analysis, reverse DNS resolution,
ASN lookup, and risk evaluation across IPv4 and IPv6 spaces.
"""

from datetime import datetime, timezone
import ipaddress
import json
import socket
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import logger
from app.core.security import is_ip_private_or_reserved
from app.models.schema_models import IPAnalysisRecord
from app.schemas.ip import IPAnalysisResponse, ThreatSignalSchema
from app.services.reputation_service import (
    check_abuseipdb,
    check_ipinfo,
    evaluate_ip_reputation,
)


def get_reverse_dns(ip_str: str) -> str:
    """Attempts PTR record lookup for an IP address."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except Exception:
        return "No PTR record found"


def query_rdap(ip_str: str) -> Dict[str, Any]:
    """Queries official Regional Internet Registry RDAP service for ASN/Org info."""
    rdap_url = f"https://rdap.arin.net/registry/ip/{ip_str}"
    headers = {"Accept": "application/rdap+json, application/json"}

    result = {
        "asn": "Unknown",
        "as_org": "Unknown",
        "country": "Unknown",
        "city": "Unknown",
    }

    try:
        with httpx.Client(timeout=3.5, follow_redirects=True) as client:
            resp = client.get(rdap_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                result["as_org"] = data.get("name", "Unknown")
                entities = data.get("entities", [])
                for ent in entities:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for prop in vcard[1]:
                            if prop[0] == "fn":
                                result["as_org"] = prop[3]
                                break
    except Exception as e:
        logger.debug(f"RDAP query skipped: {e}")

    return result


def analyze_ip_address(ip_input: str, db: Optional[Session] = None) -> IPAnalysisResponse:
    """Validates and analyzes an IPv4 or IPv6 address.

    Raises:
        ValueError on malformed IP address string.
    """
    if not ip_input or not isinstance(ip_input, str):
        raise ValueError("Invalid IP address input.")

    ip_str = ip_input.strip()

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError as e:
        raise ValueError(f"'{ip_str}' is not a valid IPv4 or IPv6 address: {e}")

    ip_version = ip_obj.version
    disallowed, reason = is_ip_private_or_reserved(ip_obj)

    created_at_val = datetime.now(timezone.utc)
    record_id = ""

    # Special handling for private/reserved/loopback addresses
    if disallowed:
        classification = "loopback" if ip_obj.is_loopback else "private" if ip_obj.is_private else "reserved"
        signals = [
            ThreatSignalSchema(
                category="network",
                indicator=f"Internal / {classification.capitalize()} Address",
                severity="info",
                confidence="confirmed",
                source="RFC 6890 / IETF",
                details=f"Address belongs to non-routable range: {reason}. No public threat intelligence exists.",
            )
        ]

        resp = IPAnalysisResponse(
            id=record_id or "local-analysis",
            ip_address=str(ip_obj),
            ip_version=ip_version,
            is_routable=False,
            classification=classification,
            asn="N/A (Private)",
            as_org="Local / Private Network",
            reverse_dns=get_reverse_dns(str(ip_obj)),
            country_code="--",
            country_name="Local Network",
            city="Private Subnet",
            is_datacenter=False,
            is_vpn=False,
            is_proxy=False,
            is_tor=False,
            reputation_score=0,
            threat_level="low",
            provider_sources={"local_analyzer": "IETF RFC 1918 / RFC 4291 Classification"},
            signals=signals,
            created_at=created_at_val,
        )

        if db is not None:
            db_record = IPAnalysisRecord(
                ip_address=resp.ip_address,
                ip_version=resp.ip_version,
                is_routable=resp.is_routable,
                classification=resp.classification,
                asn=resp.asn,
                as_org=resp.as_org,
                reverse_dns=resp.reverse_dns,
                country_code=resp.country_code,
                country_name=resp.country_name,
                city=resp.city,
                is_datacenter=resp.is_datacenter,
                is_vpn=resp.is_vpn,
                is_proxy=resp.is_proxy,
                is_tor=resp.is_tor,
                reputation_score=resp.reputation_score,
                threat_level=resp.threat_level,
                provider_sources_json=json.dumps(resp.provider_sources),
                signals_json=json.dumps([s.model_dump() for s in resp.signals]),
                created_at=created_at_val,
            )
            db.add(db_record)
            db.commit()
            resp.id = db_record.id

        return resp

    # Public Routable IP Analysis
    classification = "public"
    reverse_dns = get_reverse_dns(str(ip_obj))

    # RDAP lookup for ASN and organization
    rdap_info = query_rdap(str(ip_obj))
    as_org = rdap_info.get("as_org", "Unknown")
    asn = rdap_info.get("asn", "Unknown")
    city = rdap_info.get("city", "Unknown")
    country_name = rdap_info.get("country", "Unknown")
    country_code = "UN"

    provider_sources: Dict[str, Any] = {"rdap": "Regional Internet Registry (ARIN/RIPE)"}

    # Optional external providers
    abuse_data = None
    ipinfo_data = None

    if settings.enable_external_intelligence:
        if settings.abuseipdb_api_key:
            abuse_data = check_abuseipdb(str(ip_obj), settings.abuseipdb_api_key)
            if abuse_data:
                provider_sources["abuseipdb"] = "AbuseIPDB Community Database"

        # Check IPinfo (works with free tier or token)
        ipinfo_data = check_ipinfo(str(ip_obj), settings.ipinfo_token)
        if ipinfo_data:
            provider_sources["ipinfo"] = "IPinfo Geolocation & Privacy API"
            if ipinfo_data.get("city") and ipinfo_data.get("city") != "Unknown":
                city = ipinfo_data["city"]
            if ipinfo_data.get("country") and ipinfo_data.get("country") != "Unknown":
                country_name = ipinfo_data["country"]
                country_code = ipinfo_data["country"]
            if ipinfo_data.get("org") and ipinfo_data.get("org") != "Unknown":
                as_org = ipinfo_data["org"]

    # Calculate reputation and threat signals
    reputation_score, threat_level, threat_signals = evaluate_ip_reputation(
        ip_str=str(ip_obj),
        as_org=as_org,
        abuse_data=abuse_data,
        ipinfo_data=ipinfo_data,
    )

    is_dc = False
    is_vpn = False
    is_proxy = False
    is_tor = False

    if ipinfo_data:
        is_dc = ipinfo_data.get("is_hosting", False)
        is_vpn = ipinfo_data.get("is_vpn", False)
        is_proxy = ipinfo_data.get("is_proxy", False)
        is_tor = ipinfo_data.get("is_tor", False)

    for s in threat_signals:
        if s.indicator == "Known Tor Exit Node":
            is_tor = True
        elif "Cloud Datacenter" in s.indicator:
            is_dc = True
        elif "VPN" in s.indicator:
            is_vpn = True

    resp_signals = [ThreatSignalSchema(**s.to_dict()) for s in threat_signals]

    resp = IPAnalysisResponse(
        id="",
        ip_address=str(ip_obj),
        ip_version=ip_version,
        is_routable=True,
        classification=classification,
        asn=asn,
        as_org=as_org,
        reverse_dns=reverse_dns,
        country_code=country_code,
        country_name=country_name,
        city=city,
        is_datacenter=is_dc,
        is_vpn=is_vpn,
        is_proxy=is_proxy,
        is_tor=is_tor,
        reputation_score=reputation_score,
        threat_level=threat_level,
        provider_sources=provider_sources,
        signals=resp_signals,
        created_at=created_at_val,
    )

    if db is not None:
        db_record = IPAnalysisRecord(
            ip_address=resp.ip_address,
            ip_version=resp.ip_version,
            is_routable=resp.is_routable,
            classification=resp.classification,
            asn=resp.asn,
            as_org=resp.as_org,
            reverse_dns=resp.reverse_dns,
            country_code=resp.country_code,
            country_name=resp.country_name,
            city=resp.city,
            is_datacenter=resp.is_datacenter,
            is_vpn=resp.is_vpn,
            is_proxy=resp.is_proxy,
            is_tor=resp.is_tor,
            reputation_score=resp.reputation_score,
            threat_level=resp.threat_level,
            provider_sources_json=json.dumps(resp.provider_sources),
            signals_json=json.dumps([s.model_dump() for s in resp.signals]),
            created_at=created_at_val,
        )
        db.add(db_record)
        db.commit()
        resp.id = db_record.id
    else:
        import uuid
        resp.id = str(uuid.uuid4())

    return resp
