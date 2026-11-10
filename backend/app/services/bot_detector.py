"""BotShield Behavioral Bot Detection Engine

Multi-signal behavioral analysis evaluating request velocity, burst clustering,
endpoint probing, 404 error cascades, sequence intervals, and automation markers.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.config import settings
from app.database import utc_now
from app.models.schema_models import (
    BotDetectionResult,
    BotEvent,
    DetectionRuleConfig,
)
from app.schemas.bot import (
    BotDashboardSummary,
    BotDetectionResultSchema,
    BotEventCreate,
    PathCount,
    StatusDistribution,
    TopSuspiciousIP,
    TriggeredRuleSchema,
)

# Known programmatic automation signatures (weak signal, never single proof)
AUTOMATION_UA_PATTERNS = [
    "python-requests", "curl/", "wget/", "httpx/", "aiohttp/", "go-http-client",
    "headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
    "postmanruntime", "insomnia/", "scrapy", "sqlmap", "nikto", "masscan", "zgrab"
]

# Sensitive endpoint probes characteristic of vulnerability scanners
PROBING_TARGET_PATHS = {
    "/wp-login.php", "/wp-admin", "/.env", "/config.json", "/phpmyadmin",
    "/actuator/env", "/.git/config", "/api/v1/users", "/server-status",
    "/aws/credentials", "/id_rsa", "/backup.sql", "/admin/login"
}


def record_bot_event(event_in: BotEventCreate, db: Session) -> BotEvent:
    """Persists an inbound HTTP telemetry event."""
    event = BotEvent(
        source_ip=event_in.source_ip,
        http_method=event_in.http_method.upper(),
        path=event_in.path,
        user_agent=event_in.user_agent,
        response_status=event_in.response_status,
        duration_ms=event_in.duration_ms,
        session_id=event_in.session_id,
        is_lab_traffic=event_in.is_lab_traffic,
        lab_scenario=event_in.lab_scenario,
        timestamp=utc_now(),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def evaluate_ip_behavior(
    source_ip: str,
    db: Session,
    window_seconds: Optional[int] = None
) -> BotDetectionResultSchema:
    """Evaluates telemetry for a specific IP over a sliding window."""
    sec = window_seconds or settings.telemetry_window_seconds
    now = utc_now()
    cutoff = now - timedelta(seconds=sec)

    events: List[BotEvent] = (
        db.query(BotEvent)
        .filter(BotEvent.source_ip == source_ip, BotEvent.timestamp >= cutoff)
        .order_by(BotEvent.timestamp.asc())
        .all()
    )

    # Load dynamic rule configurations
    rule_configs = {r.id: r for r in db.query(DetectionRuleConfig).all()}

    triggered_rules: List[TriggeredRuleSchema] = []
    evidence: List[str] = []
    total_score = 0

    total_requests = len(events)
    if total_requests == 0:
        return BotDetectionResultSchema(
            id="empty-eval",
            source_ip=source_ip,
            risk_score=0,
            risk_level="low",
            window_start=cutoff,
            window_end=now,
            total_requests=0,
            status_404_count=0,
            unique_paths_count=0,
            triggered_rules=[],
            evidence=["No telemetry events recorded for this IP in the specified observation window."],
            reviewed=False,
            reviewed_by="",
            review_notes="",
            is_false_positive=False,
            created_at=now,
        )

    # Signal A: High Request Frequency
    hf_rule = rule_configs.get("HIGH_FREQUENCY")
    hf_threshold = hf_rule.threshold_value if hf_rule else settings.high_frequency_threshold
    hf_weight = hf_rule.weight if hf_rule else settings.weight_high_frequency
    hf_enabled = hf_rule.enabled if hf_rule else True

    if hf_enabled and total_requests >= hf_threshold:
        pts = hf_weight
        total_score += pts
        triggered_rules.append(TriggeredRuleSchema(
            rule_id="HIGH_FREQUENCY",
            rule_name="High Request Frequency",
            points_awarded=pts,
            threshold=hf_threshold,
            observed_value=float(total_requests),
            explanation=f"{total_requests} requests observed within {sec}s (threshold: {int(hf_threshold)})."
        ))
        evidence.append(f"High cumulative volume: {total_requests} requests in {sec}s.")

    # Signal B: Short-Window Burst Velocity (Peak requests within any 10-second interval)
    burst_rule = rule_configs.get("BURST_VELOCITY")
    burst_threshold = burst_rule.threshold_value if burst_rule else settings.burst_threshold_count
    burst_weight = burst_rule.weight if burst_rule else settings.weight_burst_velocity
    burst_enabled = burst_rule.enabled if burst_rule else True

    max_burst = 0
    if len(events) > 1:
        timestamps = [e.timestamp.timestamp() for e in events]
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > settings.burst_window_seconds:
                left += 1
            cur_burst = right - left + 1
            if cur_burst > max_burst:
                max_burst = cur_burst

    if burst_enabled and max_burst >= burst_threshold:
        pts = burst_weight
        total_score += pts
        triggered_rules.append(TriggeredRuleSchema(
            rule_id="BURST_VELOCITY",
            rule_name="Short-Window Burst Velocity",
            points_awarded=pts,
            threshold=burst_threshold,
            observed_value=float(max_burst),
            explanation=f"Peak burst of {max_burst} requests in {settings.burst_window_seconds}s (threshold: {int(burst_threshold)})."
        ))
        evidence.append(f"Rapid burst detected: {max_burst} requests clustered within {settings.burst_window_seconds}s.")

    # Signal C: Path & Endpoint Enumeration
    distinct_paths = {e.path for e in events}
    unique_paths_count = len(distinct_paths)
    ep_rule = rule_configs.get("ENDPOINT_PROBING")
    ep_threshold = ep_rule.threshold_value if ep_rule else settings.path_enumeration_threshold
    ep_weight = ep_rule.weight if ep_rule else settings.weight_endpoint_probing
    ep_enabled = ep_rule.enabled if ep_rule else True

    sensitive_matches = [p for p in distinct_paths if any(probe in p.lower() for probe in PROBING_TARGET_PATHS)]

    if ep_enabled and (unique_paths_count >= ep_threshold or len(sensitive_matches) >= 2):
        pts = ep_weight
        total_score += pts
        triggered_rules.append(TriggeredRuleSchema(
            rule_id="ENDPOINT_PROBING",
            rule_name="Path & Endpoint Enumeration",
            points_awarded=pts,
            threshold=ep_threshold,
            observed_value=float(unique_paths_count),
            explanation=(
                f"Client accessed {unique_paths_count} unique endpoints. "
                f"Probed targets include: {', '.join(sensitive_matches[:4]) or 'broad enumeration'}."
            )
        ))
        evidence.append(f"Endpoint enumeration: {unique_paths_count} distinct paths visited; {len(sensitive_matches)} sensitive probes.")

    # Signal D: Repeated 404 Errors
    status_404_count = sum(1 for e in events if e.response_status == 404)
    err_rule = rule_configs.get("EXCESSIVE_404S")
    err_threshold = err_rule.threshold_value if err_rule else settings.probing_404_threshold
    err_weight = err_rule.weight if err_rule else settings.weight_excessive_404s
    err_enabled = err_rule.enabled if err_rule else True

    if err_enabled and status_404_count >= err_threshold:
        pts = err_weight
        total_score += pts
        triggered_rules.append(TriggeredRuleSchema(
            rule_id="EXCESSIVE_404S",
            rule_name="Repeated 404 Probing",
            points_awarded=pts,
            threshold=err_threshold,
            observed_value=float(status_404_count),
            explanation=f"{status_404_count} requests resulted in HTTP 404 Not Found (threshold: {int(err_threshold)})."
        ))
        evidence.append(f"Excessive 404 responses ({status_404_count}), characteristic of blind path fuzzing.")

    # Signal E: Automation User-Agent Markers (Weak signal)
    ua_rule = rule_configs.get("AUTOMATION_USER_AGENT")
    ua_weight = ua_rule.weight if ua_rule else settings.weight_automation_user_agent
    ua_enabled = ua_rule.enabled if ua_rule else True

    known_automation_uas = set()
    empty_uas = 0
    for e in events:
        ua_str = (e.user_agent or "").strip().lower()
        if not ua_str:
            empty_uas += 1
        elif any(pattern in ua_str for pattern in AUTOMATION_UA_PATTERNS):
            known_automation_uas.add(e.user_agent)

    if ua_enabled and (known_automation_uas or empty_uas >= 3):
        pts = ua_weight
        total_score += pts
        sample_ua = next(iter(known_automation_uas)) if known_automation_uas else "Empty User-Agent"
        triggered_rules.append(TriggeredRuleSchema(
            rule_id="AUTOMATION_USER_AGENT",
            rule_name="Automation User-Agent Indicator",
            points_awarded=pts,
            threshold=1.0,
            observed_value=float(len(known_automation_uas) + (1 if empty_uas else 0)),
            explanation=f"Identified automation client signature (e.g. '{sample_ua}') or absent User-Agent."
        ))
        evidence.append(f"Automation User-Agent marker: '{sample_ua}' (Note: weak signal, corroborated with behavioral metrics).")

    # Signal F: Rate-Limit Violations (Continued requests after 429)
    status_429_count = sum(1 for e in events if e.response_status == 429)
    rl_rule = rule_configs.get("RATE_LIMIT_VIOLATIONS")
    rl_threshold = rl_rule.threshold_value if rl_rule else settings.rate_limit_violation_threshold
    rl_weight = rl_rule.weight if rl_rule else settings.weight_rate_limit_violations
    rl_enabled = rl_rule.enabled if rl_rule else True

    if rl_enabled and status_429_count >= rl_threshold:
        pts = rl_weight
        total_score += pts
        triggered_rules.append(TriggeredRuleSchema(
            rule_id="RATE_LIMIT_VIOLATIONS",
            rule_name="Rate Limit Violations",
            points_awarded=pts,
            threshold=rl_threshold,
            observed_value=float(status_429_count),
            explanation=f"Client persisted sending requests after receiving {status_429_count} HTTP 429 responses."
        ))
        evidence.append(f"Rate-limit disregard: {status_429_count} requests executed despite server 429 throttling.")

    # Signal G: Rapid / Unnatural Inter-Request Timing
    seq_rule = rule_configs.get("RAPID_SEQUENCE")
    seq_threshold = seq_rule.threshold_value if seq_rule else 0.15  # seconds
    seq_weight = seq_rule.weight if seq_rule else settings.weight_rapid_sequence
    seq_enabled = seq_rule.enabled if seq_rule else True

    avg_interval = 0.0
    if len(events) >= 5:
        deltas = [
            (events[i].timestamp - events[i - 1].timestamp).total_seconds()
            for i in range(1, len(events))
        ]
        avg_interval = sum(deltas) / len(deltas)
        if seq_enabled and avg_interval < seq_threshold:
            pts = seq_weight
            total_score += pts
            triggered_rules.append(TriggeredRuleSchema(
                rule_id="RAPID_SEQUENCE",
                rule_name="Unnatural Inter-Request Timing",
                points_awarded=pts,
                threshold=seq_threshold,
                observed_value=round(avg_interval, 3),
                explanation=f"Average inter-request interval was {round(avg_interval * 1000, 1)}ms (threshold: <{int(seq_threshold * 1000)}ms)."
            ))
            evidence.append(f"Sub-human request cadence: average spacing of {round(avg_interval * 1000, 1)}ms.")

    # Clamp total score
    final_score = min(100, max(0, total_score))

    if final_score >= settings.risk_high_max:
        risk_level = "critical"
    elif final_score >= settings.risk_moderate_max:
        risk_level = "high"
    elif final_score >= settings.risk_low_max:
        risk_level = "moderate"
    else:
        risk_level = "low"

    # Store or update evaluation in database
    db_result = (
        db.query(BotDetectionResult)
        .filter(BotDetectionResult.source_ip == source_ip)
        .order_by(BotDetectionResult.created_at.desc())
        .first()
    )

    result_id = ""
    is_fp = False
    reviewed = False
    reviewed_by = ""
    notes = ""

    # Preserve analyst review if previously reviewed
    if db_result and db_result.reviewed:
        reviewed = db_result.reviewed
        reviewed_by = db_result.reviewed_by
        notes = db_result.review_notes
        is_fp = db_result.is_false_positive

    new_db_result = BotDetectionResult(
        source_ip=source_ip,
        risk_score=final_score,
        risk_level=risk_level,
        window_start=cutoff,
        window_end=now,
        total_requests=total_requests,
        status_404_count=status_404_count,
        unique_paths_count=unique_paths_count,
        triggered_rules_json=json.dumps([r.model_dump() for r in triggered_rules]),
        evidence_json=json.dumps(evidence),
        reviewed=reviewed,
        reviewed_by=reviewed_by,
        review_notes=notes,
        is_false_positive=is_fp,
        created_at=now,
    )
    db.add(new_db_result)
    db.commit()
    result_id = new_db_result.id

    return BotDetectionResultSchema(
        id=result_id,
        source_ip=source_ip,
        risk_score=final_score,
        risk_level=risk_level,
        window_start=cutoff,
        window_end=now,
        total_requests=total_requests,
        status_404_count=status_404_count,
        unique_paths_count=unique_paths_count,
        triggered_rules=triggered_rules,
        evidence=evidence,
        reviewed=reviewed,
        reviewed_by=reviewed_by,
        review_notes=notes,
        is_false_positive=is_fp,
        created_at=now,
    )


def get_dashboard_summary(db: Session) -> BotDashboardSummary:
    """Aggregates telemetry and detection statistics from real stored events."""
    now = utc_now()
    cutoff_24h = now - timedelta(hours=24)
    cutoff_1m = now - timedelta(minutes=1)

    # 1. Total events & unique IPs
    total_events = db.query(func.count(BotEvent.id)).scalar() or 0
    unique_ips = db.query(func.count(func.distinct(BotEvent.source_ip))).scalar() or 0

    # 2. Requests in last minute (RPM)
    events_last_minute = (
        db.query(func.count(BotEvent.id))
        .filter(BotEvent.timestamp >= cutoff_1m)
        .scalar() or 0
    )

    # 3. HTTP status distribution
    status_counts = (
        db.query(BotEvent.response_status, func.count(BotEvent.id))
        .group_by(BotEvent.response_status)
        .order_by(desc(func.count(BotEvent.id)))
        .limit(10)
        .all()
    )
    status_distribution = [
        StatusDistribution(status_code=row[0], count=row[1])
        for row in status_counts
    ]

    # 4. Top requested paths
    path_counts = (
        db.query(BotEvent.path, func.count(BotEvent.id))
        .group_by(BotEvent.path)
        .order_by(desc(func.count(BotEvent.id)))
        .limit(10)
        .all()
    )
    top_paths = [
        PathCount(path=row[0], count=row[1])
        for row in path_counts
    ]

    # 5. Recent evaluations and risk counts
    recent_detections_db = (
        db.query(BotDetectionResult)
        .order_by(BotDetectionResult.created_at.desc())
        .limit(20)
        .all()
    )

    risk_dist = {"low": 0, "moderate": 0, "high": 0, "critical": 0}
    recent_detections: List[BotDetectionResultSchema] = []
    suspicious_count = 0

    for d in recent_detections_db:
        risk_dist[d.risk_level] = risk_dist.get(d.risk_level, 0) + 1
        if d.risk_score >= settings.risk_low_max:
            suspicious_count += 1

        try:
            tr_data = json.loads(d.triggered_rules_json or "[]")
            tr_schemas = [TriggeredRuleSchema(**item) for item in tr_data]
        except Exception:
            tr_schemas = []

        try:
            ev_data = json.loads(d.evidence_json or "[]")
        except Exception:
            ev_data = []

        recent_detections.append(BotDetectionResultSchema(
            id=d.id,
            source_ip=d.source_ip,
            risk_score=d.risk_score,
            risk_level=d.risk_level,
            window_start=d.window_start,
            window_end=d.window_end,
            total_requests=d.total_requests,
            status_404_count=d.status_404_count,
            unique_paths_count=d.unique_paths_count,
            triggered_rules=tr_schemas,
            evidence=ev_data,
            reviewed=d.reviewed,
            reviewed_by=d.reviewed_by or "",
            review_notes=d.review_notes or "",
            is_false_positive=d.is_false_positive or False,
            created_at=d.created_at,
        ))

    # 6. Top suspicious IPs
    top_sus_db = (
        db.query(
            BotDetectionResult.source_ip,
            func.max(BotDetectionResult.risk_score).label("max_score"),
            BotDetectionResult.risk_level,
            func.max(BotDetectionResult.total_requests).label("max_reqs"),
            func.max(BotDetectionResult.created_at).label("last_seen"),
        )
        .filter(BotDetectionResult.risk_score >= settings.risk_low_max)
        .group_by(BotDetectionResult.source_ip)
        .order_by(desc("max_score"))
        .limit(10)
        .all()
    )

    top_suspicious_ips: List[TopSuspiciousIP] = []
    for row in top_sus_db:
        top_suspicious_ips.append(TopSuspiciousIP(
            source_ip=row[0],
            risk_score=row[1],
            risk_level=row[2],
            request_count=row[3],
            last_seen=row[4],
            top_trigger="Behavioral Rule Violation",
        ))

    return BotDashboardSummary(
        total_events=total_events,
        unique_ips=unique_ips,
        suspicious_count=suspicious_count,
        requests_per_minute=float(events_last_minute),
        risk_distribution=risk_dist,
        top_suspicious_ips=top_suspicious_ips,
        top_paths=top_paths,
        status_distribution=status_distribution,
        recent_detections=recent_detections,
    )
