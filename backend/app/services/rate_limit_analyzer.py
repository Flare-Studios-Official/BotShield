"""BotShield Rate-Limit Header Analyzer Service

Passively identifies standard and vendor-specific HTTP rate-limiting headers.
"""

from typing import Dict, List, Tuple


def analyze_rate_limit_headers(headers: Dict[str, str]) -> Tuple[List[Dict[str, any]], Dict[str, any]]:
    """Analyzes response headers for rate-limit metadata.

    Returns:
        (findings_list, summary_dict)
    """
    findings = []
    h = {k.lower(): v for k, v in headers.items()}

    # Standard IETF RateLimit headers
    rl_limit = h.get("ratelimit-limit")
    rl_remaining = h.get("ratelimit-remaining")
    rl_reset = h.get("ratelimit-reset")

    # Common vendor headers
    x_rl_limit = h.get("x-ratelimit-limit") or h.get("x-rate-limit-limit")
    x_rl_remaining = h.get("x-ratelimit-remaining") or h.get("x-rate-limit-remaining")
    x_rl_reset = h.get("x-ratelimit-reset") or h.get("x-rate-limit-reset")
    retry_after = h.get("retry-after")

    observed_headers = {}
    if rl_limit:
        observed_headers["RateLimit-Limit"] = rl_limit
    if rl_remaining:
        observed_headers["RateLimit-Remaining"] = rl_remaining
    if rl_reset:
        observed_headers["RateLimit-Reset"] = rl_reset
    if x_rl_limit:
        observed_headers["X-RateLimit-Limit"] = x_rl_limit
    if x_rl_remaining:
        observed_headers["X-RateLimit-Remaining"] = x_rl_remaining
    if x_rl_reset:
        observed_headers["X-RateLimit-Reset"] = x_rl_reset
    if retry_after:
        observed_headers["Retry-After"] = retry_after

    if observed_headers:
        formatted = ", ".join(f"{k}: {v}" for k, v in observed_headers.items())
        findings.append({
            "name": "Rate-Limiting Headers Detected",
            "category": "ratelimit",
            "severity": "info",
            "observed_value": formatted,
            "description": "Target discloses request quotas and throttling thresholds via HTTP headers.",
            "implication": "Explicit rate limits help compliant clients meter traffic to avoid blocking.",
            "recommendation": "Monitor response headers to honor server capacity quotas.",
            "confidence": "confirmed",
        })
    else:
        findings.append({
            "name": "No Rate-Limiting Headers Exposed",
            "category": "ratelimit",
            "severity": "info",
            "observed_value": "Headers not present on target route",
            "description": "Standard RateLimit and X-RateLimit headers were not returned.",
            "implication": "The endpoint may enforce rate limiting silently or at upstream network gateways.",
            "recommendation": "Implement client-side backoff algorithms regardless of header disclosure.",
            "confidence": "observed",
        })

    summary = {
        "headers_found": bool(observed_headers),
        "disclosed_headers": observed_headers,
    }

    return findings, summary
