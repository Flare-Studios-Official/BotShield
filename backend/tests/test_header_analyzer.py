"""Tests for HTTP security header inspection and scoring."""

from app.services.header_analyzer import analyze_security_headers


def test_full_security_headers():
    """All recommended headers present -> score 100."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; object-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
    findings, score = analyze_security_headers(headers, is_https=True)
    assert score == 100
    assert len(findings) == 6
    for f in findings:
        assert f.severity == "info"


def test_missing_headers_penalties():
    """Missing headers reduce score with contextual severities."""
    headers = {}
    findings, score = analyze_security_headers(headers, is_https=True)
    assert score < 50
    names = [f.name for f in findings]
    assert "Strict-Transport-Security (HSTS)" in names
    assert "Content-Security-Policy (CSP)" in names
    assert "X-Content-Type-Options" in names
    assert "X-Frame-Options" in names


def test_unsafe_csp_directives():
    """Permissive CSP with unsafe-inline triggers low severity warning."""
    headers = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
    }
    findings, score = analyze_security_headers(headers, is_https=True)
    csp_finding = next(f for f in findings if "Content-Security-Policy" in f.name)
    assert csp_finding.severity == "low"
    assert "unsafe-inline" in csp_finding.description
