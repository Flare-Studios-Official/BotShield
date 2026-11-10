"""Bot Detection and Telemetry API Routes."""

import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db, utc_now
from app.models.schema_models import (
    BotDetectionResult,
    BotEvent,
    DetectionRuleConfig,
)
from app.schemas.bot import (
    BotDashboardSummary,
    BotDetectionResultSchema,
    BotEventCreate,
    BotEventSchema,
    DetectionRuleSchema,
    DetectionRuleUpdate,
    ReviewDetectionRequest,
    TriggeredRuleSchema,
)
from app.services.bot_detector import (
    evaluate_ip_behavior,
    get_dashboard_summary,
    record_bot_event,
)

router = APIRouter(prefix="/bots", tags=["Bot Detection"])


@router.post("/events", response_model=BotEventSchema)
def ingest_telemetry_event(payload: BotEventCreate, db: Session = Depends(get_db)):
    """Ingests a live HTTP telemetry event and triggers immediate behavioral evaluation."""
    ev = record_bot_event(payload, db=db)
    # Trigger background evaluation on the source IP
    evaluate_ip_behavior(payload.source_ip, db=db)
    return BotEventSchema(
        id=ev.id,
        timestamp=ev.timestamp,
        source_ip=ev.source_ip,
        http_method=ev.http_method,
        path=ev.path,
        user_agent=ev.user_agent,
        response_status=ev.response_status,
        duration_ms=ev.duration_ms,
        session_id=ev.session_id,
        is_lab_traffic=ev.is_lab_traffic,
        lab_scenario=ev.lab_scenario,
    )


@router.get("/summary", response_model=BotDashboardSummary)
def get_bot_dashboard_metrics(db: Session = Depends(get_db)):
    """Computes real-time telemetry metrics and detection distributions from stored events."""
    return get_dashboard_summary(db=db)


@router.get("/events", response_model=List[BotEventSchema])
def list_telemetry_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source_ip: str = Query(None),
    db: Session = Depends(get_db),
):
    """Retrieves chronological telemetry events with optional source IP filtering."""
    q = db.query(BotEvent)
    if source_ip:
        q = q.filter(BotEvent.source_ip == source_ip.strip())
    events = q.order_by(BotEvent.timestamp.desc()).offset(offset).limit(limit).all()

    return [
        BotEventSchema(
            id=e.id,
            timestamp=e.timestamp,
            source_ip=e.source_ip,
            http_method=e.http_method,
            path=e.path,
            user_agent=e.user_agent,
            response_status=e.response_status,
            duration_ms=e.duration_ms,
            session_id=e.session_id,
            is_lab_traffic=e.is_lab_traffic,
            lab_scenario=e.lab_scenario,
        )
        for e in events
    ]


@router.get("/evaluate/{ip_address}", response_model=BotDetectionResultSchema)
def trigger_manual_evaluation(
    ip_address: str,
    window_seconds: int = Query(300, ge=30, le=3600),
    db: Session = Depends(get_db),
):
    """Executes an on-demand behavioral evaluation for a given IP address."""
    return evaluate_ip_behavior(ip_address.strip(), db=db, window_seconds=window_seconds)


@router.get("/rules", response_model=List[DetectionRuleSchema])
def list_detection_rules(db: Session = Depends(get_db)):
    """Retrieves all detection rule definitions, active weights, and thresholds."""
    rules = db.query(DetectionRuleConfig).all()
    return [
        DetectionRuleSchema(
            id=r.id,
            name=r.name,
            description=r.description,
            weight=r.weight,
            threshold_value=r.threshold_value,
            enabled=r.enabled,
            updated_at=r.updated_at,
        )
        for r in rules
    ]


@router.put("/rules/{rule_id}", response_model=DetectionRuleSchema)
def update_detection_rule(
    rule_id: str,
    payload: DetectionRuleUpdate,
    db: Session = Depends(get_db),
):
    """Updates detection rule scoring weights, thresholds, or enabled toggle."""
    rule = db.query(DetectionRuleConfig).filter(DetectionRuleConfig.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found.")

    if payload.weight is not None:
        rule.weight = payload.weight
    if payload.threshold_value is not None:
        rule.threshold_value = payload.threshold_value
    if payload.enabled is not None:
        rule.enabled = payload.enabled

    rule.updated_at = utc_now()
    db.commit()
    db.refresh(rule)

    return DetectionRuleSchema(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        weight=rule.weight,
        threshold_value=rule.threshold_value,
        enabled=rule.enabled,
        updated_at=rule.updated_at,
    )


@router.post("/detections/{detection_id}/review", response_model=BotDetectionResultSchema)
def review_detection_record(
    detection_id: str,
    payload: ReviewDetectionRequest,
    db: Session = Depends(get_db),
):
    """Records human analyst review and false-positive determination."""
    det = db.query(BotDetectionResult).filter(BotDetectionResult.id == detection_id).first()
    if not det:
        raise HTTPException(status_code=404, detail="Detection record not found.")

    det.reviewed = True
    det.reviewed_by = payload.reviewed_by
    det.review_notes = payload.review_notes
    det.is_false_positive = payload.is_false_positive
    db.commit()
    db.refresh(det)

    try:
        tr_data = json.loads(det.triggered_rules_json or "[]")
        tr_schemas = [TriggeredRuleSchema(**item) for item in tr_data]
    except Exception:
        tr_schemas = []

    try:
        ev_data = json.loads(det.evidence_json or "[]")
    except Exception:
        ev_data = []

    return BotDetectionResultSchema(
        id=det.id,
        source_ip=det.source_ip,
        risk_score=det.risk_score,
        risk_level=det.risk_level,
        window_start=det.window_start,
        window_end=det.window_end,
        total_requests=det.total_requests,
        status_404_count=det.status_404_count,
        unique_paths_count=det.unique_paths_count,
        triggered_rules=tr_schemas,
        evidence=ev_data,
        reviewed=det.reviewed,
        reviewed_by=det.reviewed_by,
        review_notes=det.review_notes,
        is_false_positive=det.is_false_positive,
        created_at=det.created_at,
    )
