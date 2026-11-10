"""BotShield IP Reputation & Threat Intelligence Service

Provides extensible, provider-independent reputation lookups with
resilient fallbacks, timeout handling, and clear provider attribution.
"""

from typing import Any, Dict, List, Optional, Tuple
import httpx

from app.config import settings
from app.core.logging import logger

# Well-known public Datacenter/Cloud ASN keywords for heuristic matching
DATACENTER_ASN_KEYWORDS = {
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
    "linode", "ovh", "hetzner", "cloudflare", "fastly", "akamai",
    "vultr", "leaseweb", "choopa", "contabo", "oracle", "alibaba"
}

# Known Tor exit node IP addresses (sample seed; updated via official list when network available)
KNOWN_TOR_EXIT_SAMPLE = {
    "185.220.101.4", "185.220.101.5", "185.220.101.6", "185.220.101.7",
    "185.220.100.240", "185.220.100.241", "185.220.100.242", "185.220.100.243",
    "198.98.57.207", "198.98.56.143", "51.15.43.205", "171.25.193.20"
}


class ThreatSignal:
    def __init__(
        self,
        category: str,
        indicator: str,
        severity: str,
        confidence: str,
        source: str,
        details: str
    ):
        self.category = category
        self.indicator = indicator
        self.severity = severity
        self.confidence = confidence
        self.source = source
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "indicator": self.indicator,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "details": self.details,
        }


def check_abuseipdb(ip_str: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Queries official AbuseIPDB v2 check endpoint if an API key is provided."""
    if not api_key:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_str,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "provider": "AbuseIPDB",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "usage_type": data.get("usageType", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                    "last_reported_at": data.get("lastReportedAt", None),
                }
            else:
                logger.warning(f"AbuseIPDB returned status {resp.status_code}")
    except Exception as e:
        logger.debug(f"AbuseIPDB query exception: {e}")

    return None


def check_ipinfo(ip_str: str, token: str) -> Optional[Dict[str, Any]]:
    """Queries official IPinfo endpoint if a token or free access is available."""
    url = f"https://ipinfo.io/{ip_str}/json"
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                privacy = data.get("privacy", {})
                return {
                    "provider": "IPinfo",
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "hostname": data.get("hostname", ""),
                    "is_vpn": privacy.get("vpn", False),
                    "is_proxy": privacy.get("proxy", False),
                    "is_tor": privacy.get("tor", False),
                    "is_hosting": privacy.get("hosting", False),
                }
    except Exception as e:
        logger.debug(f"IPinfo query exception: {e}")

    return None


def evaluate_ip_reputation(
    ip_str: str,
    as_org: str,
    abuse_data: Optional[Dict[str, Any]],
    ipinfo_data: Optional[Dict[str, Any]],
) -> Tuple[int, str, List[ThreatSignal]]:
    """Calculates explainable risk score (0-100) and threat signals."""
    signals: List[ThreatSignal] = []
    score = 0

    # 1. Tor Exit Node Check
    is_tor = False
    if ipinfo_data and ipinfo_data.get("is_tor"):
        is_tor = True
    elif ip_str in KNOWN_TOR_EXIT_SAMPLE:
        is_tor = True

    if is_tor:
        score += 45
        signals.append(ThreatSignal(
            category="anonymization",
            indicator="Known Tor Exit Node",
            severity="high",
            confidence="confirmed",
            source="Tor Project Directory / IPinfo",
            details="IP address actively relays anonymized Tor network egress traffic."
        ))

    # 2. AbuseIPDB Reports
    if abuse_data:
        abuse_score = abuse_data.get("abuse_confidence_score", 0)
        reports = abuse_data.get("total_reports", 0)
        if abuse_score > 0:
            score += int(abuse_score * 0.5)
            sev = "critical" if abuse_score >= 75 else "high" if abuse_score >= 40 else "medium"
            signals.append(ThreatSignal(
                category="reputation",
                indicator=f"Public Abuse Reports ({reports} report{'s' if reports != 1 else ''})",
                severity=sev,
                confidence="confirmed",
                source="AbuseIPDB",
                details=f"Abuse confidence score of {abuse_score}% based on community attack reports."
            ))

    # 3. VPN / Proxy Check
    if ipinfo_data and (ipinfo_data.get("is_vpn") or ipinfo_data.get("is_proxy")):
        score += 25
        signals.append(ThreatSignal(
            category="anonymization",
            indicator="Commercial VPN / Proxy Service",
            severity="medium",
            confidence="observed",
            source="IPinfo Privacy API",
            details="IP belongs to known commercial VPN, web proxy, or egress tunnel provider."
        ))

    # 4. Datacenter / Cloud Hosting
    as_org_lower = as_org.lower()
    is_dc = False
    if ipinfo_data and ipinfo_data.get("is_hosting"):
        is_dc = True
    elif any(dc in as_org_lower for dc in DATACENTER_ASN_KEYWORDS):
        is_dc = True

    if is_dc:
        score += 15
        signals.append(ThreatSignal(
            category="infrastructure",
            indicator="Cloud Datacenter / Hosting Provider",
            severity="low",
            confidence="observed",
            source="BGP ASN Registry / IPinfo",
            details=f"Autonomous system organization ({as_org}) operates cloud/server infrastructure rather than residential broadband."
        ))

    # Clamp score
    final_score = min(100, max(0, score))

    # Threat tier
    if final_score >= settings.risk_high_max:
        threat_level = "critical"
    elif final_score >= settings.risk_moderate_max:
        threat_level = "high"
    elif final_score >= settings.risk_low_max:
        threat_level = "moderate"
    else:
        threat_level = "low"

    return final_score, threat_level, signals
