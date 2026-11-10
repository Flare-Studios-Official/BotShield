"""IP Intelligence API Routes."""

import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.schema_models import IPAnalysisRecord
from app.schemas.ip import IPAnalysisRequest, IPAnalysisResponse, ThreatSignalSchema
from app.services.ip_analyzer import analyze_ip_address

router = APIRouter(prefix="/ips", tags=["IP Intelligence"])


@router.post("/analyze", response_model=IPAnalysisResponse)
def analyze_ip_endpoint(payload: IPAnalysisRequest, db: Session = Depends(get_db)):
    """Analyzes an IPv4 or IPv6 address for reputation, ASN, classification, and risk."""
    try:
        result = analyze_ip_address(payload.ip_address, db=db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IP analysis encountered an unexpected error: {e}")


@router.get("/history", response_model=List[IPAnalysisResponse])
def get_ip_analysis_history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieves previous IP intelligence lookups."""
    records = (
        db.query(IPAnalysisRecord)
        .order_by(IPAnalysisRecord.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    results = []
    for r in records:
        try:
            sources = json.loads(r.provider_sources_json or "{}")
        except Exception:
            sources = {}

        try:
            signals_data = json.loads(r.signals_json or "[]")
            signals = [ThreatSignalSchema(**s) for s in signals_data]
        except Exception:
            signals = []

        results.append(IPAnalysisResponse(
            id=r.id,
            ip_address=r.ip_address,
            ip_version=r.ip_version,
            is_routable=r.is_routable,
            classification=r.classification,
            asn=r.asn,
            as_org=r.as_org,
            reverse_dns=r.reverse_dns,
            country_code=r.country_code,
            country_name=r.country_name,
            city=r.city,
            is_datacenter=r.is_datacenter,
            is_vpn=r.is_vpn,
            is_proxy=r.is_proxy,
            is_tor=r.is_tor,
            reputation_score=r.reputation_score,
            threat_level=r.threat_level,
            provider_sources=sources,
            signals=signals,
            created_at=r.created_at,
        ))
    return results
