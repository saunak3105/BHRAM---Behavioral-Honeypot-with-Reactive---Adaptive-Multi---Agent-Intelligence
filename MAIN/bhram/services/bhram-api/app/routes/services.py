"""
BHRAM API — Services Routes
GET /api/v1/services — list all registered services
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Service
from app.schemas import ServiceListResponse, ServiceSchema

router = APIRouter(prefix="/api/v1", tags=["Services"])


@router.get(
    "/services",
    response_model=ServiceListResponse,
    summary="List all deception environment services",
    description=(
        "Returns all services registered in the BHRAM environment, "
        "including honeypots, decoy services, and internal infrastructure. "
        "Use `is_honeypot` and `is_decoy` flags to distinguish service categories."
    ),
)
async def list_services(db: AsyncSession = Depends(get_db)) -> ServiceListResponse:
    result = await db.execute(select(Service).order_by(Service.name))
    services = result.scalars().all()

    return ServiceListResponse(
        total=len(services),
        services=[ServiceSchema.model_validate(s) for s in services],
    )
