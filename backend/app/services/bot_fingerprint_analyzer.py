"""BotShield Bot Defense & CDN Fingerprint Analyzer

Passively inspects HTTP response headers, cookies, and page challenge markers
to detect front-door bot protection and WAF vendor layers without active probing.
"""

from typing import Dict, List
from bs4 import BeautifulSoup


class BotDefenseIndicator:
    def __init__(self, provider: str, confidence: str, signals: List[str], details: str):
        self.provider = provider
        self.confidence = confidence  # confirmed, observed, heuristic
        self.signals = signals
        self.details = details

    def to_dict(self) -> Dict[str, any]:
        return {
            "name": f"Bot Protection: {self.provider}",
            "category": "bot_defense",
            "severity": "info",
            "observed_value": ", ".join(self.signals),
            "description": f"Front-door reverse proxy, WAF, or challenge layer detected ({self.provider}).",
            "implication": "Automated requests may receive JS challenges, CAPTCHAs, or silent rate-limiting.",
            "recommendation": "Maintain standard, respectful crawling etiquette conforming to robots.txt.",
            "confidence": self.confidence,
        }


def detect_bot_protection_indicators(
    headers: Dict[str, str],
    html_content: str = ""
) -> List[Dict[str, any]]:
    """Evaluates response artifacts to identify anti-bot vendor deployments.

    Only passive, non-invasive indicators are checked.
    """
    indicators: List[BotDefenseIndicator] = []
    h = {k.lower(): v for k, v in headers.items()}

    # 1. Cloudflare
    cf_ray = h.get("cf-ray")
    server = h.get("server", "").lower()
    set_cookie = h.get("set-cookie", "").lower()

    if cf_ray:
        indicators.append(BotDefenseIndicator(
            provider="Cloudflare",
            confidence="confirmed",
            signals=[f"cf-ray: {cf_ray[:12]}..."],
            details="Cloudflare edge network and potential Bot Management layer active."
        ))
    elif "cloudflare" in server:
        indicators.append(BotDefenseIndicator(
            provider="Cloudflare",
            confidence="observed",
            signals=[f"Server: {headers.get('server')}"],
            details="Cloudflare reverse proxy identified via Server response header."
        ))

    # 2. Akamai
    if any(k.startswith("x-akamai-") for k in h.keys()) or "akamai" in server:
        signals = [k for k in h.keys() if k.startswith("x-akamai-")][:2]
        if not signals and "akamai" in server:
            signals = [f"Server: {headers.get('server')}"]
        indicators.append(BotDefenseIndicator(
            provider="Akamai",
            confidence="observed",
            signals=signals or ["Akamai Edge Header"],
            details="Akamai Edge / Bot Manager infrastructure present in response headers."
        ))

    # 3. AWS CloudFront / WAF
    if "x-amz-cf-id" in h or "x-amz-cf-pop" in h:
        cf_id = h.get("x-amz-cf-id", "")
        indicators.append(BotDefenseIndicator(
            provider="AWS CloudFront",
            confidence="confirmed",
            signals=[f"x-amz-cf-id: {cf_id[:16]}..."] if cf_id else ["x-amz-cf-id"],
            details="Amazon CloudFront CDN and possible AWS WAF integration detected."
        ))

    # 4. Fastly
    if "x-fastly-request-id" in h or "fastly" in server:
        indicators.append(BotDefenseIndicator(
            provider="Fastly",
            confidence="observed",
            signals=["x-fastly-request-id"] if "x-fastly-request-id" in h else ["Server: Fastly"],
            details="Fastly CDN edge delivery with optional Signal Sciences (Fastly Next-Gen WAF)."
        ))

    # 5. DataDome
    if "datadome" in set_cookie or "x-datadome" in h:
        indicators.append(BotDefenseIndicator(
            provider="DataDome",
            confidence="confirmed",
            signals=["DataDome cookie/header"],
            details="Specialized anti-bot behavioral protection provider DataDome detected."
        ))

    # 6. Imperva / Incapsula
    if "x-iinfo" in h or "incap_ses" in set_cookie or "visid_incap" in set_cookie:
        indicators.append(BotDefenseIndicator(
            provider="Imperva Incapsula",
            confidence="confirmed",
            signals=["x-iinfo" if "x-iinfo" in h else "incap session cookie"],
            details="Imperva Cloud WAF & Advanced Bot Protection signatures identified."
        ))

    # 7. Passive HTML Challenge Checks (non-invasive inspect of title/meta)
    if html_content:
        try:
            soup = BeautifulSoup(html_content[:15000], "html.parser")
            title = soup.title.string.lower() if soup.title and soup.title.string else ""
            if "just a moment..." in title or "attention required! | cloudflare" in title:
                indicators.append(BotDefenseIndicator(
                    provider="Cloudflare Challenge",
                    confidence="confirmed",
                    signals=[f"Page title: '{title.strip()}'"],
                    details="Interactive JavaScript challenge or Managed Challenge interstitial triggered."
                ))
            elif "ddos-guard" in title:
                indicators.append(BotDefenseIndicator(
                    provider="DDoS-Guard",
                    confidence="confirmed",
                    signals=["DDoS-Guard Title"],
                    details="DDoS-Guard reverse proxy challenge page encountered."
                ))
        except Exception:
            pass

    return [ind.to_dict() for ind in indicators]
