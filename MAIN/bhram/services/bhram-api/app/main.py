"""
BHRAM API — FastAPI Application Entry Point
Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence

SECURITY NOTICE:
  - This API is bound to 127.0.0.1 only in production compose configuration.
  - It is NOT directly accessible from attacker-facing networks.
  - No arbitrary command execution is possible through this API.
  - All data returned is fictional deception environment data.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config import settings
from app.database import get_db_context
from app.routes import environment, services, users, files, events, sessions, telemetry, ai

# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="BHRAM API",
    description=(
        "**BHRAM — Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence**\n\n"
        "Internal REST API for the BHRAM deception environment.\n\n"
        "### Purpose\n"
        "This API provides the AI/ML orchestration team with a clean interface to:\n"
        "- Read the current deception environment state\n"
        "- Query registered services, users, and decoy files\n"
        "- **Monitor attack sessions and normalized telemetry events (Part 2)**\n"
        "- **Submit AI-generated attacker profiles and deception decisions (Part 2)**\n"
        "- Execute adaptive deception actions (Part 3)\n\n"
        "### Security\n"
        "- This API is bound to `127.0.0.1` and is **not** accessible from attacker networks.\n"
        "- All data is fictional — no real credentials or personal data.\n"
        "- AI decisions are **validated** against a strict allowlist before recording.\n"
        "- No arbitrary shell command execution is possible through this API.\n\n"
        "### Status: **Part 2 — Telemetry & Event Normalization Pipeline**"
    ),
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={
        "name": "BHRAM Project",
        "email": "bhram-project@university.internal",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# ── Middleware ─────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Dashboard only
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{elapsed:.2f}"
    response.headers["X-BHRAM-Version"] = settings.app_version
    return response


# ── Routers ───────────────────────────────────────────────────────────────────

# Part 1 — Foundation
app.include_router(environment.router)
app.include_router(services.router)
app.include_router(users.router)
app.include_router(files.router)

# Part 2 — Telemetry & Event Normalization Pipeline
app.include_router(events.router)
app.include_router(sessions.router)
app.include_router(telemetry.router)
app.include_router(ai.router)


# ── Health endpoint ───────────────────────────────────────────────────────────

@app.get(
    "/health",
    tags=["System"],
    summary="API and dependency health check",
    description="Returns health status of the API and its dependencies (database, etc.).",
    response_model=dict,
)
async def health_check() -> dict:
    service_statuses = []
    overall_status = "healthy"

    # ── Check database connectivity ────────────────────────────────────────────
    try:
        t0 = time.perf_counter()
        async with get_db_context() as db:
            await db.execute(text("SELECT 1"))
        db_latency = (time.perf_counter() - t0) * 1000
        service_statuses.append({
            "name": "postgres",
            "status": "healthy",
            "latency_ms": round(db_latency, 2),
        })
    except Exception as exc:
        overall_status = "degraded"
        service_statuses.append({
            "name": "postgres",
            "status": "unhealthy",
            "error": str(exc)[:200],
        })

    return {
        "status": overall_status,
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": service_statuses,
    }


# ── Root endpoint ─────────────────────────────────────────────────────────────

@app.get(
    "/",
    tags=["System"],
    summary="API root",
    include_in_schema=False,
)
async def root() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "status": "operational",
    }


# ── Exception handlers ────────────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"error": "Not found", "path": str(request.url.path), "success": False},
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "success": False},
    )
