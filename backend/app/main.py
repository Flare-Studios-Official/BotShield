"""BotShield FastAPI Main Application Entrypoint

Wires together CORS, rate-limiting, database lifecycle, security exception handlers,
and all defensive auditing and behavioral detection routers.
"""

from contextlib import asynccontextmanager
import time
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import bots, health, ips, lab, proxies, reports, websites
from app.config import settings
from app.core.logging import logger
from app.core.security import SSRFValidationError, sanitize_credentials
from app.database import init_db

# Simple in-memory token bucket rate limiter for API endpoints
CLIENT_REQUEST_COUNTS = {}
RATE_LIMIT_CEILING = 120  # requests per client IP
RATE_LIMIT_PERIOD = 60    # seconds


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes database schema and default rule configurations on boot."""
    logger.info("Initializing BotShield database schema and detection heuristics...")
    init_db()
    logger.info("BotShield platform initialized successfully.")
    yield
    logger.info("BotShield platform shutting down.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=settings.app_description,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_and_telemetry_middleware(request: Request, call_next):
    """Enforces API rate limits and automatically cleans error traces."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()

    # Clean old window records
    client_history = CLIENT_REQUEST_COUNTS.setdefault(client_ip, [])
    CLIENT_REQUEST_COUNTS[client_ip] = [ts for ts in client_history if now - ts < RATE_LIMIT_PERIOD]

    if len(CLIENT_REQUEST_COUNTS[client_ip]) >= RATE_LIMIT_CEILING:
        logger.warning(f"Rate limit exceeded for API client {client_ip}")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "Rate limit exceeded",
                "detail": f"Max {RATE_LIMIT_CEILING} requests per {RATE_LIMIT_PERIOD} seconds.",
            },
            headers={"Retry-After": str(RATE_LIMIT_PERIOD)}
        )

    CLIENT_REQUEST_COUNTS[client_ip].append(now)

    try:
        response = await call_next(request)
        return response
    except SSRFValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "SSRF Security Validation Failed", "detail": str(e)}
        )
    except Exception as exc:
        safe_msg = sanitize_credentials(str(exc))
        logger.error(f"Unhandled exception on {request.url.path}: {safe_msg}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal Server Error", "detail": "An internal error occurred during request processing."}
        )


# Register API Routers
app.include_router(health.router, prefix="/api")
app.include_router(websites.router, prefix="/api")
app.include_router(ips.router, prefix="/api")
app.include_router(bots.router, prefix="/api")
app.include_router(proxies.router, prefix="/api")
app.include_router(lab.router, prefix="/api")
app.include_router(reports.router, prefix="/api")


@app.get("/")
def root():
    return {
        "platform": settings.app_name,
        "tagline": "Understand. Detect. Defend.",
        "version": settings.app_version,
        "docs": "/api/docs",
        "health": "/api/health",
    }
