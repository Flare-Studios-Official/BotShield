"""Proxy Intelligence API Routes."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.security import SSRFValidationError
from app.database import get_db
from app.models.schema_models import ProxyTestRecord
from app.schemas.proxy import ProxyTestRequest, ProxyTestResponse
from app.services.proxy_analyzer import test_proxy_endpoint

router = APIRouter(prefix="/proxies", tags=["Proxy Intelligence"])


@router.post("/test", response_model=ProxyTestResponse)
def execute_proxy_diagnostic(payload: ProxyTestRequest, db: Session = Depends(get_db)):
    """Audits connectivity, latency, protocol support, and egress IP for a user-authorized proxy."""
    try:
        result = test_proxy_endpoint(
            proxy_url=payload.proxy_url,
            target_url=payload.target_url,
            db=db,
        )
        return result
    except SSRFValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proxy diagnostic failed: {e}")


@router.get("/history", response_model=List[ProxyTestResponse])
def list_proxy_tests(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieves previous proxy diagnostic audit records."""
    records = (
        db.query(ProxyTestRecord)
        .order_by(ProxyTestRecord.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        ProxyTestResponse(
            id=r.id,
            proxy_scheme=r.proxy_scheme,
            proxy_host=r.proxy_host,
            proxy_port=r.proxy_port,
            target_tested=r.target_tested,
            success=r.success,
            latency_ms=r.latency_ms,
            egress_ip=r.egress_ip,
            egress_classification=r.egress_classification,
            error_message=r.error_message,
            created_at=r.created_at,
        )
        for r in records
    ]
