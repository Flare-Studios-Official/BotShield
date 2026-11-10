"""BotShield Bot Protection & CDN Fingerprint Analyzer

Passively inspects headers and response cues for front-door anti-bot
and WAF architectures, with calibrated confidence and transparent limitations.
"""

from typing import Any, Dict, List


class BotDefenseIndicator:
    def __init__(
        self,
        provider: str,
        confidence: str,  # confirmed, observed, possible
        evidence: str,
        limitations: str,
    ):
        self.provider = provider
        self.confidence = confidence
        self.evidence = evidence
        self.limitations = limitations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": f"Bot Protection / CDN: {self.provider}",
            "category": "bot_defense",
            "severity": "info",
            "observed_value": self.evidence,
            "description": f"Observed network edge indicators associated with {self.provider}.",
            "implication": (
                f"Website appears fronted by {self.provider}. Incoming traffic may be filtered "
                f"by reputation, behavioral heuristics, and challenge pages."
            ),
            "recommendation": "Maintain edge protection policies and review false-positive block logs periodically.",
            "confidence": self.confidence,
            "limitations": self.limitations,
        }


def detect_bot_protection_indicators(headers: Dict[str, str], html_content: str = "") -> List[Dict[str, Any]]:
    """Analyzes headers and public response cues for WAF and anti-bot systems."""
    h = {k.lower(): v for k, v in headers.items()}
    html_lower = (html_content or "")[:20000].lower()  # inspect first 20KB only
    indicators: List[BotDefenseIndicator] = []

    # 1. Cloudflare
    cf_ray = h.get("cf-ray")
    cf_cache = h.get("cf-cache-status")
    server = h.get("server", "").lower()
    set_cookie = h.get("set-cookie", "").lower()

    if cf_ray:
        indicators.append(BotDefenseIndicator(
            provider="Cloudflare",
            confidence="confirmed",
            evidence=f"Header cf-ray: {cf_ray}, Server: {h.get('server', 'N/A')}",
            limitations="Presence of Cloudflare edge proxy does not guarantee that Bot Management or Turnstile is enabled for this specific path."
        ))
    elif "cloudflare" in server:
        indicators.append(BotDefenseIndicator(
            provider="Cloudflare",
            confidence="observed",
            evidence=f"Server header: {h.get('server')}",
            limitations="Edge routing active; bot management tier configuration cannot be determined from passive inspection alone."
        ))

    # 2. Akamai
    if "akamai" in server or "x-akamai-transformed" in h or "akamai-grn" in h:
        indicators.append(BotDefenseIndicator(
            provider="Akamai Edge / Bot Manager",
            confidence="confirmed" if "x-akamai-transformed" in h else "observed",
            evidence="Akamai edge transformation / tracking headers identified.",
            limitations="Cannot confirm whether Akamai Bot Manager behavioral models are actively filtering unauthenticated requests."
        ))

    # 3. AWS CloudFront / AWS WAF
    if "x-amz-cf-id" in h or "x-amzn-waf-action" in h or "cloudfront" in server:
        waf_action = h.get("x-amzn-waf-action")
        indicators.append(BotDefenseIndicator(
            provider="AWS CloudFront / AWS WAF",
            confidence="confirmed" if waf_action or "x-amz-cf-id" in h else "observed",
            evidence=f"CloudFront ID or WAF header detected (x-amz-cf-id: {bool('x-amz-cf-id' in h)}, action: {waf_action or 'N/A'})",
            limitations="CloudFront can be used purely as a CDN without AWS WAF Bot Control rules enabled."
        ))

    # 4. DataDome
    if "x-datadome-response" in h or "datadome=" in set_cookie or "datadome.js" in html_lower:
        indicators.append(BotDefenseIndicator(
            provider="DataDome",
            confidence="confirmed",
            evidence="DataDome response header, cookie token, or telemetry script detected.",
            limitations="DataDome operates inline or via API; threshold sensitivities cannot be measured non-invasively."
        ))

    # 5. Imperva / Incapsula
    if "x-iinfo" in h or "x-cdn" in h and "incapsula" in h.get("x-cdn", "").lower() or "visid_incap" in set_cookie:
        indicators.append(BotDefenseIndicator(
            provider="Imperva (Incapsula)",
            confidence="confirmed",
            evidence="Imperva / Incapsula session tracking headers detected.",
            limitations="Passive inspection indicates edge presence; specific client challenge triggers remain opaque."
        ))

    # 6. Fastly
    if "x-fastly-request-id" in h or "fastly" in server:
        indicators.append(BotDefenseIndicator(
            provider="Fastly Edge",
            confidence="confirmed" if "x-fastly-request-id" in h else "observed",
            evidence=f"Fastly request tracking header present ({h.get('x-fastly-request-id', 'N/A')}).",
            limitations="Fastly edge proxies do not imply Signal Sciences / Next-Gen WAF deployment without inspection of challenge behavior."
        ))

    # 7. Sucuri
    if "x-sucuri-id" in h or "sucuri" in server:
        indicators.append(BotDefenseIndicator(
            provider="Sucuri Cloudproxy",
            confidence="confirmed",
            evidence=f"Sucuri firewall header observed ({h.get('x-sucuri-id', 'N/A')}).",
            limitations="Underlying web application host is shielded; internal protection policies unknown."
        ))

    if not indicators:
        return [{
            "name": "Bot Defense / WAF Edge",
            "category": "bot_defense",
            "severity": "info",
            "observed_value": "No recognized WAF/anti-bot vendor signatures in passive response",
            "description": "No prominent third-party CDN or anti-bot provider headers were detected.",
            "implication": "The website may be served directly by origin servers or utilize in-house / silent defense layers.",
            "recommendation": "Verify whether origin IP addresses are properly protected from direct bypass.",
            "confidence": "observed",
            "limitations": "Web applications can strip provider headers or run anti-bot analysis strictly via server-side middleware."
        }]

    return [ind.to_dict() for ind in indicators]
