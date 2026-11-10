"""BotShield Proxy Intelligence Analyzer Service

Performs defensive diagnostics and connectivity auditing on authorized
proxy endpoints with credential redaction and SSRF safety controls.
"""

from datetime import datetime, timezone
import time
from typing import Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import logger
from app.core.security import (
    ResponseSizeLimitExceeded,
    SSRFValidationError,
    sanitize_credentials,
    stream_safe_get,
    validate_and_resolve_url,
)
from app.models.schema_models import ProxyTestRecord
from app.schemas.proxy import ProxyTestResponse
from app.services.ip_analyzer import analyze_ip_address

# Safe controlled endpoints to verify proxy egress
EGRESS_CHECK_ENDPOINTS = [
    "https://api.ipify.org?format=json",
    "https://httpbin.org/ip",
]


def test_proxy_endpoint(
    proxy_url: str,
    target_url: Optional[str] = None,
    db: Optional[Session] = None
) -> ProxyTestResponse:
    """Audits connectivity and egress characteristics of a user-authorized proxy.

    Raises:
        SSRFValidationError if proxy host or target resolves to a private network.
    """
    clean_proxy = proxy_url.strip()
    parsed_proxy = urlparse(clean_proxy)

    if parsed_proxy.scheme not in ("http", "https", "socks5", "socks5h"):
        raise SSRFValidationError(
            f"Unsupported proxy scheme '{parsed_proxy.scheme}'. Permitted: http, https, socks5."
        )

    proxy_host = parsed_proxy.hostname
    proxy_port = parsed_proxy.port
    if not proxy_host or not proxy_port:
        raise SSRFValidationError("Proxy URL must include both valid hostname/IP and port.")

    # 1. SSRF Safety check on proxy host itself (do not test internal proxies on loopback/LAN)
    validate_and_resolve_url(
        f"http://{proxy_host}:{proxy_port}",
        allow_private=not settings.disallow_private_networks,
        allow_custom_ports=True
    )

    # 2. Validate target destination if provided
    test_target = target_url or EGRESS_CHECK_ENDPOINTS[0]
    validate_and_resolve_url(
        test_target,
        allow_private=False
    )

    start_time = time.perf_counter()
    success = False
    egress_ip = ""
    error_msg = ""
    egress_class = "Unknown"

    try:
        with httpx.Client(
            proxy=clean_proxy,
            timeout=settings.http_timeout_seconds,
            verify=True
        ) as client:
            resp, body_bytes = stream_safe_get(
                client=client,
                url=test_target,
                max_bytes=128 * 1024,
                timeout=settings.http_timeout_seconds,
            )
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

            if resp.status_code == 200:
                success = True
                try:
                    data = resp.json()
                    egress_ip = data.get("ip") or data.get("origin") or ""
                    # Handle multiple IPs in origin
                    if "," in egress_ip:
                        egress_ip = egress_ip.split(",")[0].strip()
                except Exception:
                    egress_ip = "Resolved (Non-JSON egress body)"
            else:
                error_msg = f"Target responded with HTTP {resp.status_code}"

    except ResponseSizeLimitExceeded as e:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        error_msg = f"Egress test payload exceeded size limits: {e}"
        logger.debug(f"Proxy test size limit exceeded: {error_msg}")

    except Exception as e:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        error_msg = sanitize_credentials(str(e))
        logger.debug(f"Proxy test failed: {error_msg}")

    # Analyze egress IP if discovered
    if success and egress_ip and egress_ip != "Resolved (Non-JSON egress body)":
        try:
            ip_eval = analyze_ip_address(egress_ip, db=None)
            tags = []
            if ip_eval.is_datacenter:
                tags.append("Datacenter")
            if ip_eval.is_vpn:
                tags.append("VPN")
            if ip_eval.is_tor:
                tags.append("Tor Exit")
            if ip_eval.as_org and ip_eval.as_org != "Unknown":
                tags.append(ip_eval.as_org)
            egress_class = " / ".join(tags) if tags else "Residential / Broadband"
        except Exception:
            egress_class = "Public Egress"

    created_at_val = datetime.now(timezone.utc)
    record_id = ""

    if db is not None:
        db_record = ProxyTestRecord(
            proxy_scheme=parsed_proxy.scheme,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            target_tested=test_target,
            success=success,
            latency_ms=latency_ms,
            egress_ip=egress_ip,
            egress_classification=egress_class,
            error_message=error_msg,
            created_at=created_at_val,
        )
        db.add(db_record)
        db.commit()
        record_id = db_record.id
    else:
        import uuid
        record_id = str(uuid.uuid4())

    return ProxyTestResponse(
        id=record_id,
        proxy_scheme=parsed_proxy.scheme,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        target_tested=test_target,
        success=success,
        latency_ms=latency_ms,
        egress_ip=egress_ip,
        egress_classification=egress_class,
        error_message=error_msg,
        created_at=created_at_val,
    )
