"""BotShield Rate-Limit Indicator Analyzer

Passively inspects HTTP response headers for standardized and vendor-specific
rate limiting parameters without intrusive request flooding.
"""

from typing import Any, Dict, List, Tuple


def analyze_rate_limit_headers(headers: Dict[str, str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Inspects response headers for active rate-limiting telemetry.

    Returns:
        (findings_list, summary_dict)
    """
    h = {k.lower(): v for k, v in headers.items()}
    findings: List[Dict[str, Any]] = []

    # Standard IETF RateLimit headers (RFC draft)
    rl_limit = h.get("ratelimit-limit")
    rl_remaining = h.get("ratelimit-remaining")
    rl_reset = h.get("ratelimit-reset")

    # Legacy & Vendor-specific headers
    x_rl_limit = h.get("x-ratelimit-limit") or h.get("x-rate-limit-limit")
    x_rl_remaining = h.get("x-ratelimit-remaining") or h.get("x-rate-limit-remaining")
    x_rl_reset = h.get("x-ratelimit-reset") or h.get("x-rate-limit-reset")
    retry_after = h.get("retry-after")

    observed_headers = {}
    if rl_limit: observed_headers["RateLimit-Limit"] = rl_limit
    if rl_remaining: observed_headers["RateLimit-Remaining"] = rl_remaining
    if rl_reset: observed_headers["RateLimit-Reset"] = rl_reset
    if x_rl_limit: observed_headers["X-RateLimit-Limit"] = x_rl_limit
    if x_rl_remaining: observed_headers["X-RateLimit-Remaining"] = x_rl_remaining
    if x_rl_reset: observed_headers["X-RateLimit-Reset"] = x_rl_reset
    if retry_after: observed_headers["Retry-After"] = retry_after

    if observed_headers:
        formatted = ", ".join(f"{k}: {v}" for k, v in observed_headers.items())
        findings.append({
            "name": "Rate-Limiting Headers Detected",
            "category": "ratelimit",
            "severity": "info",
            "observed_value": formatted,
            "description": "The server exposes explicit rate-limiting telemetry in its response headers.",
            "implication": "Clients can programmatically monitor quota consumption, reducing inadvertent 429 throttling.",
            "recommendation": "Maintain standardized IETF RateLimit-* headers across public endpoints.",
            "confidence": "confirmed",
        })
        summary = {
            "status": "observed",
            "evidence": formatted,
            "details": "Passive inspection identified operational rate-limit tracking headers.",
            "headers": observed_headers,
        }
    else:
        findings.append({
            "name": "Passive Rate-Limit Verification",
            "category": "ratelimit",
            "severity": "info",
            "observed_value": "No rate-limit headers in baseline response",
            "description": "Rate limiting could not be conclusively verified from passive single-request inspection.",
            "implication": "The web application may enforce rate limiting silently, enforce it only after a threshold, or lack request throttling.",
            "recommendation": "Ensure public APIs and login forms implement explicit rate-limiting and return 429 Too Many Requests when exceeded.",
            "confidence": "observed",
        })
        summary = {
            "status": "unverified",
            "evidence": "None in single passive response",
            "details": "Rate limiting could not be conclusively verified from passive inspection alone.",
            "headers": {},
        }

    return findings, summary
