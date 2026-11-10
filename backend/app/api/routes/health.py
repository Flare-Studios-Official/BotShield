"""Health check endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.config import settings
from app.database import get_db

router = APIRouter(tags=["Health"])


@router.get("/health")
def get_health_status(db: Session = Depends(get_db)):
    """Validates API responsiveness, database connectivity, and environment."""
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "status": "online" if db_ok else "degraded",
        "app": settings.app_name,
        "version": settings.app_version,
        "database": "connected" if db_ok else "disconnected",
        "environment": settings.environment,
        "external_intelligence_enabled": settings.enable_external_intelligence,
    }
