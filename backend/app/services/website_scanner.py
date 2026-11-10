"""BotShield Website Security Scanner Service

Orchestrates defensive HTTP analysis, SSRF-safe redirect traversal,
DNS rebinding prevention via connection-level IP pinning, TLS certificate auditing,
streaming body limit enforcement, security header checks, and bot protection profiling.
"""

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import certifi
import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import logger
from app.core.security import (
    ResponseSizeLimitExceeded,
    SSRFValidationError,
    create_pinned_client,
    stream_safe_get,
    validate_and_resolve_url,
)
from app.models.schema_models import WebsiteFinding, WebsiteScan
from app.schemas.website import RedirectHopSchema, WebsiteScanResponse
from app.services.bot_fingerprint_analyzer import detect_bot_protection_indicators
from app.services.header_analyzer import analyze_security_headers
from app.services.rate_limit_analyzer import analyze_rate_limit_headers
from app.services.robots_analyzer import parse_robots_txt


def get_tls_certificate_info(resolved_ip: str, hostname: str, port: int = 443) -> Tuple[str, str, str]:
    """Safely extracts TLS version, certificate issuer, and expiration date.

    Connects directly to the SSRF-validated IP to prevent DNS rebinding,
    while specifying server_hostname for SNI and strict certificate verification.
    """
    tls_version = "Unknown"
    issuer = "Unknown"
    expiry = "Unknown"

    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((resolved_ip, port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version() or "TLS"
                cert = ssock.getpeercert()
                if cert:
                    # Parse issuer
                    issuer_tuples = cert.get("issuer", ())
                    for item in issuer_tuples:
                        for key, val in item:
                            if key == "organizationName":
                                issuer = val
                                break
                    if issuer == "Unknown" and issuer_tuples:
                        # Fallback to commonName
                        for item in issuer_tuples:
                            for key, val in item:
                                if key == "commonName":
                                    issuer = val
                                    break
                    expiry = cert.get("notAfter", "Unknown")
    except Exception as e:
        logger.debug(f"TLS certificate check failed for {hostname} ({resolved_ip}:{port}): {e}")
        tls_version = "TLS Check Failed"

    return tls_version, issuer, expiry


def scan_website(target_url: str, db: Optional[Session] = None) -> WebsiteScanResponse:
    """Executes a complete, safe passive security assessment of a website.

    Guarantees:
        - Outbound connection is pinned strictly to the validated IP (prevents DNS rebinding / TOCTOU).
        - TLS SNI and server certificate validation remain strictly active.
        - Every redirect hop is independently re-resolved and re-validated.
        - HTTP streaming response limit is strictly enforced (immediate abort).
        - robots.txt retrieval uses identical SSRF and response-limit guardrails.

    Raises:
        SSRFValidationError on private IP or disallowed destination.
        ResponseSizeLimitExceeded if response size limit is breached.
        httpx.HTTPError on network timeout or connection failure.
    """
    start_time = time.perf_counter()

    # 1. SSRF Validation & DNS Resolution of initial target
    clean_url, resolved_ip, port, hostname = validate_and_resolve_url(
        target_url,
        allow_private=not settings.disallow_private_networks
    )

    # 2. TLS inspection if HTTPS (connecting directly to resolved_ip with SNI=hostname)
    is_target_https = clean_url.startswith("https://")
    tls_version, cert_issuer, cert_expiry = ("N/A", "N/A", "N/A")
    if is_target_https:
        tls_version, cert_issuer, cert_expiry = get_tls_certificate_info(resolved_ip, hostname, port)

    # 3. HTTP Request with SSRF-safe IP-pinned redirect traversal
    redirect_chain: List[RedirectHopSchema] = []
    current_url = clean_url
    final_response = None
    final_body_bytes = b""
    hops = 0

    headers = {
        "User-Agent": "BotShield-Security-Auditor/1.0 (+https://github.com/Flare-Studios-Official/BotShield)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    while hops <= settings.max_redirects:
        # Re-validate destination on every hop to prevent redirect-based SSRF
        hop_clean_url, hop_ip, hop_port, hop_host = validate_and_resolve_url(
            current_url,
            allow_private=not settings.disallow_private_networks
        )

        try:
            # Create a pinned HTTPX client dedicated to this hop's verified IP
            with create_pinned_client(
                pinned_hosts={hop_host: hop_ip},
                allow_private=not settings.disallow_private_networks,
                timeout=settings.http_timeout_seconds,
            ) as client:
                resp, body_bytes = stream_safe_get(
                    client=client,
                    url=hop_clean_url,
                    headers=headers,
                    max_bytes=settings.max_response_body_bytes,
                    timeout=settings.http_timeout_seconds,
                )
        except ResponseSizeLimitExceeded as e:
            raise SSRFValidationError(f"Response size exceeded safety limits: {e}")
        except httpx.RequestError as e:
            raise SSRFValidationError(f"Connection to '{hop_host}' ({hop_ip}) failed: {e}")

        redirect_chain.append(RedirectHopSchema(
            step=hops,
            url=hop_clean_url,
            status_code=resp.status_code,
            resolved_ip=hop_ip
        ))

        if resp.is_redirect and "location" in resp.headers and hops < settings.max_redirects:
            location = resp.headers["location"]
            current_url = urljoin(hop_clean_url, location)
            hops += 1
        else:
            final_response = resp
            final_body_bytes = body_bytes
            break

    if final_response is None:
        raise SSRFValidationError("Failed to obtain a final HTTP response.")

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    final_url = str(final_response.url)
    resp_headers = dict(final_response.headers)
    status_code = final_response.status_code
    content_type = resp_headers.get("content-type", "unknown")
    content_length = len(final_body_bytes)
    server_header = resp_headers.get("server", "hidden")
    https_enforced = final_url.startswith("https://")

    # Safe HTML snippet for fingerprint checks (bounded to first 20KB)
    html_text = ""
    if "text" in content_type or "html" in content_type:
        try:
            html_text = final_body_bytes[:20000].decode("utf-8", errors="replace")
        except Exception:
            pass

    # 4. Security Header Analysis
    header_findings, security_score = analyze_security_headers(resp_headers, is_https=https_enforced)

    # 5. robots.txt Analysis with connection-level IP pinning and streaming limit
    parsed_final = urlparse(final_url)
    robots_url = f"{parsed_final.scheme}://{parsed_final.netloc}/robots.txt"
    robots_content = ""
    robots_status = 404

    try:
        r_clean_url, r_ip, r_port, r_host = validate_and_resolve_url(
            robots_url,
            allow_private=not settings.disallow_private_networks
        )
        with create_pinned_client(
            pinned_hosts={r_host: r_ip},
            allow_private=not settings.disallow_private_networks,
            timeout=4.0,
        ) as robots_client:
            r_resp, r_bytes = stream_safe_get(
                client=robots_client,
                url=r_clean_url,
                headers=headers,
                max_bytes=min(settings.max_response_body_bytes, 128 * 1024),
                timeout=4.0,
            )
            robots_status = r_resp.status_code
            if r_resp.status_code == 200:
                robots_content = r_bytes[:50000].decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug(f"robots.txt retrieval skipped or failed: {e}")

    robots_result = parse_robots_txt(robots_content, robots_status)

    # 6. Rate-Limit Indicators
    ratelimit_findings, ratelimit_summary = analyze_rate_limit_headers(resp_headers)

    # 7. Bot-Protection Indicators
    bot_defense_findings = detect_bot_protection_indicators(resp_headers, html_text)

    # Consolidate all findings
    all_findings_dicts = []
    for hf in header_findings:
        all_findings_dicts.append(hf.to_dict())
    all_findings_dicts.extend(robots_result.findings)
    all_findings_dicts.extend(ratelimit_findings)
    all_findings_dicts.extend(bot_defense_findings)

    # 8. Store in Database
    scan_id = ""
    created_at_val = datetime.now(timezone.utc)

    if db is not None:
        import json
        chain_json = json.dumps([h.model_dump() for h in redirect_chain])
        db_scan = WebsiteScan(
            target_url=clean_url,
            final_url=final_url,
            resolved_ip=resolved_ip,
            status_code=status_code,
            response_time_ms=duration_ms,
            https_enforced=https_enforced,
            tls_version=tls_version,
            tls_cert_issuer=cert_issuer,
            tls_cert_expiry=cert_expiry,
            content_type=content_type,
            content_length=content_length,
            server_header=server_header,
            redirect_count=len(redirect_chain) - 1,
            redirect_chain_json=chain_json,
            security_score=security_score,
            created_at=created_at_val,
        )
        db.add(db_scan)
        db.flush()  # assign db_scan.id

        scan_id = db_scan.id

        for f_data in all_findings_dicts:
            db_finding = WebsiteFinding(
                scan_id=scan_id,
                category=f_data.get("category", "header"),
                name=f_data.get("name", "Finding"),
                severity=f_data.get("severity", "info"),
                observed_value=f_data.get("observed_value", ""),
                description=f_data.get("description", ""),
                implication=f_data.get("implication", ""),
                recommendation=f_data.get("recommendation", ""),
                confidence=f_data.get("confidence", "confirmed"),
            )
            db.add(db_finding)

        db.commit()
    else:
        import uuid
        scan_id = str(uuid.uuid4())

    from app.schemas.website import WebsiteFindingSchema
    findings_schemas = [
        WebsiteFindingSchema(
            id=f.get("id", str(idx)),
            category=f["category"],
            name=f["name"],
            severity=f["severity"],
            observed_value=f["observed_value"],
            description=f["description"],
            implication=f["implication"],
            recommendation=f["recommendation"],
            confidence=f["confidence"],
        )
        for idx, f in enumerate(all_findings_dicts)
    ]

    return WebsiteScanResponse(
        id=scan_id,
        target_url=clean_url,
        final_url=final_url,
        resolved_ip=resolved_ip,
        status_code=status_code,
        response_time_ms=duration_ms,
        https_enforced=https_enforced,
        tls_version=tls_version,
        tls_cert_issuer=cert_issuer,
        tls_cert_expiry=cert_expiry,
        content_type=content_type,
        content_length=content_length,
        server_header=server_header,
        redirect_count=len(redirect_chain) - 1,
        redirect_chain=redirect_chain,
        security_score=security_score,
        findings=findings_schemas,
        created_at=created_at_val,
    )
