"""BotShield Behavioral Bot Detection Engine Service

Core analytical engine evaluating sliding window request frequencies,
burst velocity, endpoint enumeration, 404 cascades, and timing cadence.
"""

from collections import Counter
from datetime import timedelta
import json
from typing import List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import logger
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
    TriggeredRuleSchema,
)

AUTOMATED_USER_AGENTS = {
    "curl", "python-requests", "postmanruntime", "insomnia", "aiohttp",
    "httpclient", "scrapy", "urllib", "zgrab", "nikto", "masscan",
    "nmap", "go-http-client", "apache-httpclient", "java/", "libwww-perl",
    "wget", "headlesschrome", "phantomjs", "puppeteer", "playwright"
}

SENSITIVE_PROBE_PATHS = {
    "/wp-login.php", "/wp-admin", "/admin", "/.env", "/config.json", "/phpmyadmin",
    "/actuator/env", "/.git/config", "/api/v1/users", "/server-status", "/backup.zip",
    "/v2/_catalog", "/aws/credentials", "/.aws/config", "/id_rsa", "/debug/vars"
}


def record_bot_event(payload: BotEventCreate, db: Session) -> BotEvent:
    """Stores an incoming HTTP request telemetry record with UTC timestamping."""
    now = utc_now()
    ev = BotEvent(
        source_ip=payload.source_ip.strip(),
        http_method=payload.http_method.upper(),
        path=payload.path.strip() or "/",
        user_agent=payload.user_agent.strip(),
        response_status=payload.response_status,
        duration_ms=payload.duration_ms,
        session_id=payload.session_id.strip() if payload.session_id else None,
        is_lab_traffic=payload.is_lab_traffic,
        lab_scenario=payload.lab_scenario.strip() if payload.lab_scenario else None,
        timestamp=now,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


def evaluate_ip_behavior(
    source_ip: str,
    db: Session,
    window_seconds: Optional[int] = None
) -> BotDetectionResultSchema:
    """Executes multi-rule behavioral heuristics on an IP's recent activity window."""
    clean_ip = source_ip.strip()
    window = window_seconds or settings.telemetry_window_seconds
    now = utc_now()
    window_start = now - timedelta(seconds=window)

    # 1. Fetch telemetry events within window
    events: List[BotEvent] = (
        db.query(BotEvent)
        .filter(BotEvent.source_ip == clean_ip)
        .filter(BotEvent.timestamp >= window_start)
        .order_by(BotEvent.timestamp.asc())
        .all()
    )

    total_requests = len(events)
    if total_requests == 0:
        # No recent activity on record
        return BotDetectionResultSchema(
            id="clean-baseline",
            source_ip=clean_ip,
            risk_score=0,
            risk_level="low",
            window_start=window_start,
            window_end=now,
            total_requests=0,
            status_404_count=0,
            unique_paths_count=0,
            triggered_rules=[],
            evidence=[],
            reviewed=False,
            is_false_positive=False,
            created_at=now,
        )

    # 2. Load active rule weights & thresholds from database
    rules_cfg = {r.id: r for r in db.query(DetectionRuleConfig).filter(DetectionRuleConfig.enabled.is_(True)).all()}

    triggered: List[TriggeredRuleSchema] = []
    evidence: List[dict] = []
    score = 0

    # ---------------- Rule 1: High Request Frequency ----------------
    r1 = rules_cfg.get("HIGH_FREQUENCY")
    threshold_freq = r1.threshold_value if r1 else float(settings.high_frequency_threshold)
    weight_freq = r1.weight if r1 else settings.weight_high_frequency

    if total_requests >= threshold_freq:
        score += weight_freq
        triggered.append(TriggeredRuleSchema(
            rule_id="HIGH_FREQUENCY",
            rule_name="High Request Frequency",
            points_awarded=weight_freq,
            threshold=threshold_freq,
            observed_value=float(total_requests),
            explanation=f"Client generated {total_requests} requests within {window}s window (threshold: {int(threshold_freq)})."
        ))
        evidence.append({
            "type": "frequency_spike",
            "metric": f"{total_requests} requests / {window}s",
            "implication": "Excessive throughput indicates automated crawling, scraping, or stress testing."
        })

    # ---------------- Rule 2: Short-Window Burst Velocity ----------------
    r2 = rules_cfg.get("BURST_VELOCITY")
    threshold_burst = r2.threshold_value if r2 else float(settings.burst_threshold_count)
    weight_burst = r2.weight if r2 else settings.weight_burst_velocity

    burst_cutoff = now - timedelta(seconds=settings.burst_window_seconds)
    burst_count = sum(1 for e in events if e.timestamp >= burst_cutoff)

    if burst_count >= threshold_burst:
        score += weight_burst
        triggered.append(TriggeredRuleSchema(
            rule_id="BURST_VELOCITY",
            rule_name="Short-Window Burst Velocity",
            points_awarded=weight_burst,
            threshold=threshold_burst,
            observed_value=float(burst_count),
            explanation=f"Generated {burst_count} requests within {settings.burst_window_seconds}s burst window (threshold: {int(threshold_burst)})."
        ))
        evidence.append({
            "type": "velocity_burst",
            "metric": f"{burst_count} reqs in {settings.burst_window_seconds}s",
            "implication": "Micro-burst volume exceeds human interactive capability."
        })

    # ---------------- Rule 3: Path & Endpoint Enumeration ----------------
    r3 = rules_cfg.get("ENDPOINT_PROBING")
    threshold_enum = r3.threshold_value if r3 else float(settings.path_enumeration_threshold)
    weight_enum = r3.weight if r3 else settings.weight_endpoint_probing

    unique_paths = list({e.path for e in events})
    unique_paths_count = len(unique_paths)

    # Check for specific sensitive endpoint probing
    probed_sensitive = [p for p in unique_paths if any(s in p.lower() for s in SENSITIVE_PROBE_PATHS)]

    if unique_paths_count >= threshold_enum or len(probed_sensitive) >= 2:
        score += weight_enum
        triggered.append(TriggeredRuleSchema(
            rule_id="ENDPOINT_PROBING",
            rule_name="Path & Endpoint Enumeration",
            points_awarded=weight_enum,
            threshold=threshold_enum,
            observed_value=float(unique_paths_count),
            explanation=f"Client systematically explored {unique_paths_count} unique endpoints ({len(probed_sensitive)} known attack vectors)."
        ))
        evidence.append({
            "type": "path_probing",
            "metric": f"{unique_paths_count} distinct paths",
            "implication": f"Targeting sensitive assets including: {', '.join(probed_sensitive[:3]) if probed_sensitive else 'broad scanning'}."
        })

    # ---------------- Rule 4: Repeated 404 Probing ----------------
    r4 = rules_cfg.get("EXCESSIVE_404S")
    threshold_404 = r4.threshold_value if r4 else float(settings.probing_404_threshold)
    weight_404 = r4.weight if r4 else settings.weight_excessive_404s

    count_404 = sum(1 for e in events if e.response_status == 404)

    if count_404 >= threshold_404:
        score += weight_404
        triggered.append(TriggeredRuleSchema(
            rule_id="EXCESSIVE_404S",
            rule_name="Repeated 404 Probing",
            points_awarded=weight_404,
            threshold=threshold_404,
            observed_value=float(count_404),
            explanation=f"Encountered {count_404} HTTP 404 errors during navigation (threshold: {int(threshold_404)})."
        ))
        evidence.append({
            "type": "404_cascade",
            "metric": f"{count_404} not-found responses",
            "implication": "High 404 ratio indicates blind endpoint discovery or directory fuzzing."
        })

    # ---------------- Rule 5: Automation User-Agent Indicator ----------------
    r5 = rules_cfg.get("AUTOMATION_USER_AGENT")
    weight_ua = r5.weight if r5 else settings.weight_automation_user_agent

    ua_matches = []
    for e in events:
        ua_lower = e.user_agent.lower()
        for bot_sig in AUTOMATED_USER_AGENTS:
            if bot_sig in ua_lower:
                ua_matches.append(bot_sig)
                break

    if ua_matches:
        score += weight_ua
        most_common_ua = Counter(ua_matches).most_common(1)[0][0]
        triggered.append(TriggeredRuleSchema(
            rule_id="AUTOMATION_USER_AGENT",
            rule_name="Automation User-Agent Indicator",
            points_awarded=weight_ua,
            threshold=1.0,
            observed_value=float(len(ua_matches)),
            explanation=f"Client identified as programmatic automation tool/library: '{most_common_ua}'."
        ))
        evidence.append({
            "type": "automation_user_agent",
            "metric": f"{len(ua_matches)} requests matching '{most_common_ua}'",
            "implication": "Corroborates automated scripting rather than standard human browsing."
        })

    # ---------------- Rule 6: Rate Limit Violations ----------------
    r6 = rules_cfg.get("RATE_LIMIT_VIOLATIONS")
    threshold_429 = r6.threshold_value if r6 else float(settings.rate_limit_violation_threshold)
    weight_429 = r6.weight if r6 else settings.weight_rate_limit_violations

    count_429 = sum(1 for e in events if e.response_status == 429)

    if count_429 >= threshold_429:
        score += weight_429
        triggered.append(TriggeredRuleSchema(
            rule_id="RATE_LIMIT_VIOLATIONS",
            rule_name="Rate Limit Violations",
            points_awarded=weight_429,
            threshold=threshold_429,
            observed_value=float(count_429),
            explanation=f"Client persistently sent {count_429} requests after receiving HTTP 429 Too Many Requests responses."
        ))
        evidence.append({
            "type": "rate_limit_abuse",
            "metric": f"{count_429} requests after 429 throttling",
            "implication": "Failure to back off following HTTP 429 confirms automated disregard for server controls."
        })

    # ---------------- Rule 7: Rapid Cadence / Low Interval Variance ----------------
    r7 = rules_cfg.get("RAPID_SEQUENCE")
    threshold_timing = r7.threshold_value if r7 else 0.15  # seconds
    weight_timing = r7.weight if r7 else settings.weight_rapid_sequence

    if len(events) >= 5:
        # Calculate inter-request delta times
        intervals = []
        for i in range(1, len(events)):
            delta = (events[i].timestamp - events[i - 1].timestamp).total_seconds()
            if delta >= 0:
                intervals.append(delta)

        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            # Rapid deterministic pace
            if avg_interval < threshold_timing:
                score += weight_timing
                triggered.append(TriggeredRuleSchema(
                    rule_id="RAPID_SEQUENCE",
                    rule_name="Unnatural Inter-Request Timing",
                    points_awarded=weight_timing,
                    threshold=threshold_timing,
                    observed_value=round(avg_interval, 3),
                    explanation=f"Average interval between requests was {round(avg_interval * 1000, 1)}ms (threshold: {int(threshold_timing * 1000)}ms)."
                ))
                evidence.append({
                    "type": "sub_human_cadence",
                    "metric": f"{round(avg_interval * 1000, 1)}ms mean interval",
                    "implication": "Continuous high-speed request dispatch lacks human read/interaction latency."
                })

    # 3. Clamp final risk score and assign risk tier
    final_score = min(100, max(0, score))

    if final_score >= settings.risk_high_max:
        risk_level = "critical"
    elif final_score >= settings.risk_moderate_max:
        risk_level = "high"
    elif final_score >= settings.risk_low_max:
        risk_level = "moderate"
    else:
        risk_level = "low"

    # 4. Save detection snapshot to database
    det_record = BotDetectionResult(
        source_ip=clean_ip,
        risk_score=final_score,
        risk_level=risk_level,
        window_start=window_start,
        window_end=now,
        total_requests=total_requests,
        status_404_count=count_404,
        unique_paths_count=unique_paths_count,
        triggered_rules_json=json.dumps([t.model_dump() for t in triggered]),
        evidence_json=json.dumps(evidence),
        reviewed=False,
        is_false_positive=False,
        created_at=now,
    )
    db.add(det_record)
    db.commit()
    db.refresh(det_record)

    return BotDetectionResultSchema(
        id=det_record.id,
        source_ip=clean_ip,
        risk_score=final_score,
        risk_level=risk_level,
        window_start=window_start,
        window_end=now,
        total_requests=total_requests,
        status_404_count=count_404,
        unique_paths_count=unique_paths_count,
        triggered_rules=triggered,
        evidence=evidence,
        reviewed=False,
        is_false_positive=False,
        created_at=now,
    )


def get_dashboard_summary(db: Session) -> BotDashboardSummary:
    """Aggregates telemetry and detection statistics from real stored events."""
    now = utc_now()
    cutoff_1m = now - timedelta(minutes=1)

    # 1. Total events & unique IPs
    total_events = db.query(func.count(BotEvent.id)).scalar() or 0
    unique_ips = db.query(func.count(func.distinct(BotEvent.source_ip))).scalar() or 0

    # 2. Requests in last minute (RPM)
    events_last_minute = (
        db.query(func.count(BotEvent.id))
        .filter(BotEvent.timestamp >= cutoff_1m)
        .scalar()
        or 0
    )

    # 3. Detection tier distribution
    detections = db.query(BotDetectionResult).all()
    tier_counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    for d in detections:
        lvl = d.risk_level.lower()
        if lvl in tier_counts:
            tier_counts[lvl] += 1

    # 4. Top probed paths
    path_counts = (
        db.query(BotEvent.path, func.count(BotEvent.id).label("count"))
        .group_by(BotEvent.path)
        .order_by(desc("count"))
        .limit(8)
        .all()
    )
    top_paths = [{"path": p, "count": c} for p, c in path_counts]

    # 5. Traffic velocity timeseries (simulated 10-bucket curve for visual trends)
    buckets = []
    for i in range(10, 0, -1):
        bucket_start = now - timedelta(minutes=i * 2)
        bucket_end = now - timedelta(minutes=(i - 1) * 2)
        c = (
            db.query(func.count(BotEvent.id))
            .filter(BotEvent.timestamp >= bucket_start)
            .filter(BotEvent.timestamp < bucket_end)
            .scalar()
            or 0
        )
        buckets.append({"time": bucket_end.strftime("%H:%M"), "requests": c})

    return BotDashboardSummary(
        total_events=total_events,
        unique_ips=unique_ips,
        requests_last_minute=events_last_minute,
        critical_detections_count=tier_counts["critical"],
        high_detections_count=tier_counts["high"],
        moderate_detections_count=tier_counts["moderate"],
        low_detections_count=tier_counts["low"],
        top_probed_paths=top_paths,
        traffic_velocity_series=buckets,
        risk_tier_distribution=tier_counts,
    )
