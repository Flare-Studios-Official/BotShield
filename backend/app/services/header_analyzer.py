"""BotShield Security Header Analyzer

Deep analysis of HTTP security headers with context-aware severity scoring
and practical remediation guidance.
"""

from typing import Any, Dict, List, Tuple


class HeaderAnalysisResult:
    def __init__(
        self,
        name: str,
        severity: str,
        observed_value: str,
        description: str,
        implication: str,
        recommendation: str,
        confidence: str = "confirmed",
        score_penalty: int = 0
    ):
        self.name = name
        self.severity = severity
        self.observed_value = observed_value
        self.description = description
        self.implication = implication
        self.recommendation = recommendation
        self.confidence = confidence
        self.score_penalty = score_penalty

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": "header",
            "severity": self.severity,
            "observed_value": self.observed_value,
            "description": self.description,
            "implication": self.implication,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


def analyze_security_headers(headers: Dict[str, str], is_https: bool) -> Tuple[List[HeaderAnalysisResult], int]:
    """Analyzes response headers and computes a security score (0-100).

    Returns:
        (findings_list, calculated_score)
    """
    findings: List[HeaderAnalysisResult] = []
    # Normalize header keys to lowercase
    h = {k.lower(): v for k, v in headers.items()}
    score = 100

    # 1. Strict-Transport-Security (HSTS)
    hsts = h.get("strict-transport-security")
    if not is_https:
        findings.append(HeaderAnalysisResult(
            name="Strict-Transport-Security (HSTS)",
            severity="info",
            observed_value=hsts or "Not applicable (HTTP target)",
            description="Enforces secure HTTPS transport for all subsequent connections.",
            implication="HSTS headers are ignored by browsers over plain HTTP connections.",
            recommendation="Migrate the site to HTTPS and configure HSTS with max-age >= 31536000.",
            confidence="confirmed",
            score_penalty=5
        ))
    elif not hsts:
        findings.append(HeaderAnalysisResult(
            name="Strict-Transport-Security (HSTS)",
            severity="medium",
            observed_value="Header missing",
            description="Enforces secure HTTPS transport and protects against SSL stripping attacks.",
            implication="Vulnerable to man-in-the-middle downgrade attacks on insecure Wi-Fi or networks.",
            recommendation="Add header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            confidence="confirmed",
            score_penalty=15
        ))
    else:
        hsts_lower = hsts.lower()
        if "max-age" not in hsts_lower:
            findings.append(HeaderAnalysisResult(
                name="Strict-Transport-Security (HSTS)",
                severity="medium",
                observed_value=hsts,
                description="HSTS header present but lacks valid 'max-age' directive.",
                implication="Browsers will disregard the HSTS policy without a max-age lifetime.",
                recommendation="Specify max-age: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                confidence="confirmed",
                score_penalty=10
            ))
        else:
            findings.append(HeaderAnalysisResult(
                name="Strict-Transport-Security (HSTS)",
                severity="info",
                observed_value=hsts,
                description="HSTS correctly configured to enforce HTTPS transport.",
                implication="Protects against protocol downgrade and cookie hijacking.",
                recommendation="Ensure 'includeSubDomains' and HSTS preload submission are planned if applicable.",
                confidence="confirmed",
                score_penalty=0
            ))

    # 2. Content-Security-Policy (CSP)
    csp = h.get("content-security-policy")
    if not csp:
        findings.append(HeaderAnalysisResult(
            name="Content-Security-Policy (CSP)",
            severity="medium",
            observed_value="Header missing",
            description="Restricts approved sources of scripts, styles, objects, and frames.",
            implication="Absence of CSP significantly increases impact of Cross-Site Scripting (XSS) and data exfiltration.",
            recommendation="Define a restrictive CSP policy starting with 'default-src \\'self\\' ; object-src \\'none\\''.",
            confidence="confirmed",
            score_penalty=20
        ))
    else:
        csp_lower = csp.lower()
        if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
            findings.append(HeaderAnalysisResult(
                name="Content-Security-Policy (CSP)",
                severity="low",
                observed_value=csp,
                description="CSP is enabled but permits 'unsafe-inline' or 'unsafe-eval' script execution.",
                implication="Reduces protection against inline XSS script injections.",
                recommendation="Replace inline scripts with cryptographic nonces (nonce-*) or SHA hashes.",
                confidence="confirmed",
                score_penalty=8
            ))
        else:
            findings.append(HeaderAnalysisResult(
                name="Content-Security-Policy (CSP)",
                severity="info",
                observed_value=csp,
                description="Robust Content-Security-Policy is active.",
                implication="Effectively constrains unauthorized resource injection and XSS.",
                recommendation="Regularly audit CSP directives and test with report-uri or report-to.",
                confidence="confirmed",
                score_penalty=0
            ))

    # 3. X-Content-Type-Options
    xcto = h.get("x-content-type-options")
    if not xcto:
        findings.append(HeaderAnalysisResult(
            name="X-Content-Type-Options",
            severity="low",
            observed_value="Header missing",
            description="Prevents MIME-type sniffing where browsers execute untrusted assets as HTML/JS.",
            implication="User-uploaded non-executable files (e.g. images) could be interpreted and run as scripts.",
            recommendation="Add header: 'X-Content-Type-Options: nosniff'.",
            confidence="confirmed",
            score_penalty=10
        ))
    elif xcto.strip().lower() != "nosniff":
        findings.append(HeaderAnalysisResult(
            name="X-Content-Type-Options",
            severity="low",
            observed_value=xcto,
            description="Invalid value for X-Content-Type-Options.",
            implication="Browsers only recognize 'nosniff' for this header.",
            recommendation="Set value to exactly 'nosniff'.",
            confidence="confirmed",
            score_penalty=5
        ))
    else:
        findings.append(HeaderAnalysisResult(
            name="X-Content-Type-Options",
            severity="info",
            observed_value=xcto,
            description="MIME-sniffing protection enabled with 'nosniff'.",
            implication="Browsers strictly adhere to declared MIME types.",
            recommendation="Maintain header on all API and static file responses.",
            confidence="confirmed",
            score_penalty=0
        ))

    # 4. X-Frame-Options
    xfo = h.get("x-frame-options")
    if not xfo and ("frame-ancestors" not in (csp or "").lower()):
        findings.append(HeaderAnalysisResult(
            name="X-Frame-Options",
            severity="low",
            observed_value="Header missing",
            description="Controls whether the site can be embedded within <frame>, <iframe>, or <object> tags.",
            implication="Increases susceptibility to Clickjacking attacks where users are tricked into clicking hidden elements.",
            recommendation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or configure CSP 'frame-ancestors'.",
            confidence="confirmed",
            score_penalty=10
        ))
    elif xfo:
        findings.append(HeaderAnalysisResult(
            name="X-Frame-Options",
            severity="info",
            observed_value=xfo,
            description=f"Clickjacking protection configured ({xfo}).",
            implication="Unauthorized framing of sensitive pages is restricted.",
            recommendation="Note that CSP frame-ancestors is the modern replacement and takes precedence.",
            confidence="confirmed",
            score_penalty=0
        ))

    # 5. Referrer-Policy
    rp = h.get("referrer-policy")
    if not rp:
        findings.append(HeaderAnalysisResult(
            name="Referrer-Policy",
            severity="low",
            observed_value="Header missing",
            description="Governs how much referrer information (URL paths, query parameters) is shared with external sites.",
            implication="Sensitive tokens, IDs, or internal URLs in query strings may leak in HTTP Referer headers.",
            recommendation="Add header: 'Referrer-Policy: strict-origin-when-cross-origin'.",
            confidence="confirmed",
            score_penalty=5
        ))
    else:
        findings.append(HeaderAnalysisResult(
            name="Referrer-Policy",
            severity="info",
            observed_value=rp,
            description=f"Referrer-Policy configured ({rp}).",
            implication="Controls path and origin leakage on outbound navigational links.",
            recommendation="Ensure query parameters never contain sensitive credentials regardless of policy.",
            confidence="confirmed",
            score_penalty=0
        ))

    # 6. Permissions-Policy (Feature-Policy)
    pp = h.get("permissions-policy") or h.get("feature-policy")
    if not pp:
        findings.append(HeaderAnalysisResult(
            name="Permissions-Policy",
            severity="info",
            observed_value="Header missing",
            description="Explicitly enables or disables browser features (camera, microphone, geolocation, payment).",
            implication="Third-party embedded iframes or scripts might request powerful device permissions.",
            recommendation="Add header: 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
            confidence="confirmed",
            score_penalty=5
        ))
    else:
        findings.append(HeaderAnalysisResult(
            name="Permissions-Policy",
            severity="info",
            observed_value=pp,
            description="Permissions-Policy explicitly delegates device capabilities.",
            implication="Prevents embedded iframes from surreptitiously accessing hardware sensors.",
            recommendation="Review permitted features whenever introducing new vendor embeds.",
            confidence="confirmed",
            score_penalty=0
        ))

    # Calculate final score
    penalties = sum(f.score_penalty for f in findings)
    final_score = max(0, min(100, score - penalties))

    return findings, final_score
