"""Website Security Scanner API Routes."""

import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.security import SSRFValidationError
from app.database import get_db
from app.models.schema_models import WebsiteFinding, WebsiteScan
from app.schemas.website import (
    RedirectHopSchema,
    WebsiteFindingSchema,
    WebsiteScanRequest,
    WebsiteScanResponse,
    WebsiteScanSummary,
)
from app.services.website_scanner import scan_website

router = APIRouter(prefix="/websites", tags=["Website Security"])


@router.post("/scan", response_model=WebsiteScanResponse)
def execute_website_scan(payload: WebsiteScanRequest, db: Session = Depends(get_db)):
    """Executes a defensive passive security scan against an authorized target website."""
    try:
        result = scan_website(payload.target_url, db=db)
        return result
    except SSRFValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Target scan failed: {e}")


@router.get("/scans", response_model=List[WebsiteScanSummary])
def list_website_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieves paginated scan history."""
    scans = (
        db.query(WebsiteScan)
        .order_by(WebsiteScan.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    summaries = []
    for s in scans:
        finding_count = db.query(WebsiteFinding).filter(WebsiteFinding.scan_id == s.id).count()
        summaries.append(WebsiteScanSummary(
            id=s.id,
            target_url=s.target_url,
            status_code=s.status_code,
            security_score=s.security_score,
            finding_count=finding_count,
            created_at=s.created_at,
        ))
    return summaries


@router.get("/scans/{scan_id}", response_model=WebsiteScanResponse)
def get_website_scan_detail(scan_id: str, db: Session = Depends(get_db)):
    """Retrieves a detailed scan report with findings and redirect hops."""
    scan = db.query(WebsiteScan).filter(WebsiteScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings_db = db.query(WebsiteFinding).filter(WebsiteFinding.scan_id == scan.id).all()
    findings_schemas = [
        WebsiteFindingSchema(
            id=f.id,
            category=f.category,
            name=f.name,
            severity=f.severity,
            observed_value=f.observed_value,
            description=f.description,
            implication=f.implication,
            recommendation=f.recommendation,
            confidence=f.confidence,
        )
        for f in findings_db
    ]

    try:
        chain_data = json.loads(scan.redirect_chain_json or "[]")
        chain_schemas = [RedirectHopSchema(**item) for item in chain_data]
    except Exception:
        chain_schemas = []

    return WebsiteScanResponse(
        id=scan.id,
        target_url=scan.target_url,
        final_url=scan.final_url,
        resolved_ip=scan.resolved_ip,
        status_code=scan.status_code,
        response_time_ms=scan.response_time_ms,
        https_enforced=scan.https_enforced,
        tls_version=scan.tls_version,
        tls_cert_issuer=scan.tls_cert_issuer,
        tls_cert_expiry=scan.tls_cert_expiry,
        content_type=scan.content_type,
        content_length=scan.content_length,
        server_header=scan.server_header,
        redirect_count=scan.redirect_count,
        redirect_chain=chain_schemas,
        security_score=scan.security_score,
        findings=findings_schemas,
        created_at=scan.created_at,
    )
