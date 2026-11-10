"""BotShield IP Intelligence Analyzer Service

Performs standards-compliant IP analysis, multi-RIR RDAP discovery, reverse DNS resolution,
ASN differentiation, and risk evaluation across IPv4 and IPv6 spaces.
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
from app.core.security import is_ip_private_or_reserved, stream_safe_get
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
    """Queries Regional Internet Registry RDAP services with multi-RIR discovery and fallback.

    Note on Standards:
    IP RDAP endpoints return network registration information (IP range name, handle,
    registrant organization), NOT Autonomous System Numbers (ASN).
    BGP ASNs require routing table lookups or dedicated ASN intelligence providers.
    """
    # Multi-RIR query endpoints in order of discovery
    endpoints = [
        ("ARIN", f"https://rdap.arin.net/registry/ip/{ip_str}"),
        ("RIPE", f"https://rdap.db.ripe.net/ip/{ip_str}"),
        ("APNIC", f"https://rdap.apnic.net/ip/{ip_str}"),
        ("LACNIC", f"https://rdap.lacnic.net/rdap/ip/{ip_str}"),
    ]
    headers = {"Accept": "application/rdap+json, application/json"}

    result = {
        "network_name": "Unknown",
        "network_handle": "Unknown",
        "registered_org": "Unknown",
        "country": "Unknown",
        "rir_source": "None",
    }

    for rir_name, url in endpoints:
        try:
            with httpx.Client(timeout=3.5, follow_redirects=True) as client:
                resp, body_bytes = stream_safe_get(
                    client=client,
                    url=url,
                    headers=headers,
                    max_bytes=512 * 1024,
                    timeout=3.5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result["network_name"] = data.get("name", "Unknown")
                    result["network_handle"] = data.get("handle", "Unknown")
                    result["country"] = data.get("country", "Unknown")
                    result["rir_source"] = f"{rir_name} RDAP"

                    # Parse registered organization from entities
                    entities = data.get("entities", [])
                    found_org = False
                    for ent in entities:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if prop[0] == "fn" and prop[3]:
                                    result["registered_org"] = prop[3]
                                    found_org = True
                                    break
                        if found_org:
                            break

                    if result["registered_org"] == "Unknown" and result["network_name"] != "Unknown":
                        result["registered_org"] = result["network_name"]

                    # Discovery succeeded, stop query loop
                    break
        except Exception as e:
            logger.debug(f"{rir_name} RDAP query skipped or timed out: {e}")
            continue

    return result


def analyze_ip_address(ip_input: str, db: Optional[Session] = None) -> IPAnalysisResponse:
    """Validates and analyzes an IPv4 or IPv6 address.

    Accurately distinguishes IP RDAP network registration data from BGP ASN routing data.
    Never labels an unverified IP as malicious.

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
                source="RFC 6890 / IANA Registry",
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

    # RDAP lookup for IP network registration details
    rdap_info = query_rdap(str(ip_obj))
    registered_org = rdap_info.get("registered_org", "Unknown")
    network_name = rdap_info.get("network_name", "Unknown")
    city = "Unknown"
    country_name = rdap_info.get("country", "Unknown")
    country_code = rdap_info.get("country", "UN")[:2].upper() if rdap_info.get("country") != "Unknown" else "UN"

    # In strict accordance with RFC 7483 / 9083, IP RDAP delivers network blocks, not BGP AS numbers
    asn = "Not resolved via IP RDAP (BGP ASN requires routing table or provider lookup)"
    as_org = registered_org if registered_org != "Unknown" else network_name

    provider_sources: Dict[str, Any] = {}
    if rdap_info.get("rir_source") != "None":
        provider_sources["rdap"] = rdap_info["rir_source"]
    else:
        provider_sources["rdap"] = "Unreachable / Offline"

    # Optional external threat intelligence providers
    abuse_data = None
    ipinfo_data = None

    if settings.enable_external_intelligence:
        if settings.abuseipdb_api_key:
            abuse_data = check_abuseipdb(str(ip_obj), settings.abuseipdb_api_key)
            if abuse_data:
                provider_sources["abuseipdb"] = "AbuseIPDB Community Database (Live)"
            else:
                provider_sources["abuseipdb"] = "AbuseIPDB (No Reports / Query Failed)"

        # Check IPinfo if configured
        ipinfo_data = check_ipinfo(str(ip_obj), settings.ipinfo_token)
        if ipinfo_data:
            provider_sources["ipinfo"] = "IPinfo Geolocation & Privacy API"
            if ipinfo_data.get("city") and ipinfo_data.get("city") != "Unknown":
                city = ipinfo_data["city"]
            if ipinfo_data.get("country") and ipinfo_data.get("country") != "Unknown":
                country_name = ipinfo_data["country"]
                country_code = ipinfo_data["country"][:2].upper()
            if ipinfo_data.get("org") and ipinfo_data.get("org") != "Unknown":
                org_val = ipinfo_data["org"]
                # IPinfo returns ASN + Org name like "AS15169 Google LLC"
                if org_val.startswith("AS"):
                    parts = org_val.split(" ", 1)
                    asn = parts[0]
                    as_org = parts[1] if len(parts) > 1 else org_val
                else:
                    as_org = org_val

    # Calculate explainable reputation score and threat signals
    reputation_score, threat_level, threat_signals, is_tor_detected = evaluate_ip_reputation(
        ip_str=str(ip_obj),
        as_org=as_org,
        abuse_data=abuse_data,
        ipinfo_data=ipinfo_data,
    )

    is_dc = False
    is_vpn = False
    is_proxy = False
    is_tor = is_tor_detected

    if ipinfo_data:
        is_dc = ipinfo_data.get("is_hosting", False)
        is_vpn = ipinfo_data.get("is_vpn", False)
        is_proxy = ipinfo_data.get("is_proxy", False)
        is_tor = is_tor or ipinfo_data.get("is_tor", False)

    for s in threat_signals:
        if "Tor Exit" in s.indicator:
            is_tor = True
        elif "Datacenter" in s.indicator:
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
