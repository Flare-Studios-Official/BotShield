"""BotShield IP Reputation & Threat Intelligence Service

Provides extensible, provider-independent reputation lookups with
live Tor directory caching, resilient fallbacks, streaming response limits,
and strict policy: never label an unverified IP as malicious.
"""

import time
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx

from app.config import settings
from app.core.logging import logger
from app.core.security import stream_safe_get

# Well-known public Datacenter/Cloud ASN keywords for heuristic matching
DATACENTER_ASN_KEYWORDS = {
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
    "linode", "ovh", "hetzner", "cloudflare", "fastly", "akamai",
    "vultr", "leaseweb", "choopa", "contabo", "oracle", "alibaba"
}

# Live Tor exit list cache (1 hour TTL)
_TOR_EXIT_CACHE: Dict[str, Any] = {
    "timestamp": 0.0,
    "ips": set(),
}
TOR_CACHE_TTL = 3600.0  # 1 hour
TOR_BULK_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"


def get_live_tor_exit_set(timeout: float = 3.5) -> Optional[Set[str]]:
    """Retrieves current Tor exit nodes from the official Tor Project directory.

    Caches results in memory for 1 hour. Uses streaming with strict 2MB response limit.
    Returns None if the official list is unreachable (offline / test environment).
    """
    global _TOR_EXIT_CACHE
    now = time.time()
    cached_ips: Set[str] = _TOR_EXIT_CACHE["ips"]

    if cached_ips and (now - _TOR_EXIT_CACHE["timestamp"]) < TOR_CACHE_TTL:
        return cached_ips

    try:
        with httpx.Client(timeout=timeout) as client:
            resp, body_bytes = stream_safe_get(
                client=client,
                url=TOR_BULK_EXIT_LIST_URL,
                max_bytes=2 * 1024 * 1024,
                timeout=timeout,
            )
            if resp.status_code == 200:
                text = body_bytes.decode("utf-8", errors="replace")
                ips = {
                    line.strip()
                    for line in text.splitlines()
                    if line.strip() and not line.startswith("#")
                }
                if ips:
                    _TOR_EXIT_CACHE["timestamp"] = now
                    _TOR_EXIT_CACHE["ips"] = ips
                    logger.info(f"Retrieved {len(ips)} live Tor exit nodes from Tor Project.")
                    return ips
    except Exception as e:
        logger.debug(f"Tor Project exit list retrieval unavailable: {e}")

    # Return cached data if available even if slightly stale
    if cached_ips:
        return cached_ips

    return None


def check_tor_exit_node(
    ip_str: str,
    ipinfo_data: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str, str]:
    """Determines whether an IP address is an active Tor exit node.

    Returns:
        (is_tor, confidence, source_description)
        confidence: 'confirmed', 'observed', or 'unverified'
    """
    # 1. Check IPinfo verified privacy data
    if ipinfo_data and ipinfo_data.get("is_tor"):
        return True, "confirmed", "IPinfo Privacy Intelligence"

    # 2. Check official Tor Project bulk exit list
    tor_set = get_live_tor_exit_set()
    if tor_set is not None:
        if ip_str in tor_set:
            return True, "confirmed", "Tor Project Official Exit Directory"
        return False, "confirmed", "Tor Project Official Exit Directory"

    # 3. Directory unreachable and no commercial feed configured
    return False, "unverified", "Tor Directory Unavailable"


class ThreatSignal:
    def __init__(
        self,
        category: str,
        indicator: str,
        severity: str,
        confidence: str,
        source: str,
        details: str,
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
        "Accept": "application/json",
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp, body_bytes = stream_safe_get(
                client=client,
                url=f"{url}?ipAddress={ip_str}&maxAgeInDays=90&verbose=true",
                headers=headers,
                max_bytes=256 * 1024,
                timeout=4.0,
            )
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
            resp, body_bytes = stream_safe_get(
                client=client,
                url=url,
                headers=headers,
                max_bytes=256 * 1024,
                timeout=4.0,
            )
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
) -> Tuple[int, str, List[ThreatSignal], bool]:
    """Calculates explainable risk score (0-100) and threat signals.

    Adheres strictly to the defensive intelligence standard:
    - Never labels an unverified IP as malicious.
    - Datacenter hosting is an infrastructure context, not proof of malice.
    - Tor detection relies on live official Tor Project directory or verified commercial feeds.

    Returns:
        (reputation_score, threat_level, signals, is_tor)
    """
    signals: List[ThreatSignal] = []
    score = 0

    # 1. Tor Exit Node Check (Live official Tor directory or IPinfo verified privacy)
    is_tor, tor_conf, tor_src = check_tor_exit_node(ip_str=ip_str, ipinfo_data=ipinfo_data)
    if is_tor:
        score += 45
        signals.append(ThreatSignal(
            category="anonymization",
            indicator="Confirmed Tor Exit Node",
            severity="high",
            confidence=tor_conf,
            source=tor_src,
            details="IP address actively relays anonymized Tor network egress traffic.",
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
                indicator=f"Community Abuse Reports ({reports} report{'s' if reports != 1 else ''})",
                severity=sev,
                confidence="confirmed",
                source="AbuseIPDB",
                details=f"Abuse confidence score of {abuse_score}% based on documented attack reports.",
            ))

    # 3. Commercial VPN / Proxy Check
    if ipinfo_data and (ipinfo_data.get("is_vpn") or ipinfo_data.get("is_proxy")):
        score += 20
        signals.append(ThreatSignal(
            category="anonymization",
            indicator="Commercial VPN / Proxy Service",
            severity="medium",
            confidence="observed",
            source="IPinfo Privacy API",
            details="IP belongs to known commercial VPN, web proxy, or egress tunnel provider.",
        ))

    # 4. Datacenter / Cloud Infrastructure
    # Datacenter hosting is an infrastructure indicator, NOT evidence of malice.
    as_org_lower = as_org.lower()
    is_dc = False
    if ipinfo_data and ipinfo_data.get("is_hosting"):
        is_dc = True
    elif any(dc in as_org_lower for dc in DATACENTER_ASN_KEYWORDS):
        is_dc = True

    if is_dc:
        # Minimal informational score (+5) so legitimate websites hosted on cloud are not penalized
        score += 5
        signals.append(ThreatSignal(
            category="infrastructure",
            indicator="Cloud Datacenter / Hosting Infrastructure",
            severity="info",
            confidence="observed",
            source="BGP Routing / IP RDAP",
            details=f"Network entity ({as_org}) operates datacenter or cloud hosting facilities rather than residential broadband.",
        ))

    # If no threats were identified, document that explicitly
    if not signals:
        signals.append(ThreatSignal(
            category="reputation",
            indicator="Clean / Neutral Public Reputation",
            severity="info",
            confidence="observed",
            source="BotShield Threat Intelligence",
            details="No documented abuse reports or malicious indicators found in active threat feeds. Unverified public address.",
        ))

    # Clamp score between 0 and 100
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

    return final_score, threat_level, signals, is_tor
