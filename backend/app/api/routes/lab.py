"""Detection Lab Simulation API Routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.lab import LabScenarioStartRequest
from app.services.traffic_simulator import reset_lab_events, run_lab_scenario

router = APIRouter(prefix="/lab", tags=["Detection Lab"])


@router.post("/run")
def execute_lab_simulation(payload: LabScenarioStartRequest, db: Session = Depends(get_db)):
    """Executes a controlled traffic scenario against local demonstration endpoints."""
    valid_scenarios = [
        "normal_browser",
        "automated_scraper",
        "burst_bot",
        "endpoint_enumeration",
        "rate_limit_offender",
    ]
    if payload.scenario not in valid_scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario '{payload.scenario}'. Permitted: {', '.join(valid_scenarios)}"
        )

    result = run_lab_scenario(
        scenario=payload.scenario,
        request_count=payload.request_count,
        interval_ms=payload.interval_ms,
        db=db,
    )
    return result


@router.post("/reset")
def clear_lab_telemetry(db: Session = Depends(get_db)):
    """Clears demonstration lab events while preserving real production telemetry."""
    deleted_count = reset_lab_events(db=db)
    return {
        "status": "success",
        "message": f"Cleared {deleted_count} lab demonstration events.",
        "deleted_count": deleted_count,
    }
