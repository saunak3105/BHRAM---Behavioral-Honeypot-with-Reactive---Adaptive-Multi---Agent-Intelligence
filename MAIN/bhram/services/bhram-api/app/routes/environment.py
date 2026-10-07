"""
BHRAM API — Environment Routes
GET /api/v1/environment  — current environment state
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import EnvironmentState
from app.schemas import EnvironmentStateSchema

router = APIRouter(prefix="/api/v1", tags=["Environment"])


@router.get(
    "/environment",
    response_model=EnvironmentStateSchema,
    summary="Get current environment state",
    description=(
        "Returns the complete current deception environment state. "
        "This is the primary read interface for AI/ML orchestration agents. "
        "The state includes active deception mode, services, users, decoys, and network topology."
    ),
)
async def get_environment(db: AsyncSession = Depends(get_db)) -> EnvironmentStateSchema:
    # Fetch the current environment state record
    result = await db.execute(
        select(EnvironmentState)
        .where(EnvironmentState.is_current == True)
        .order_by(EnvironmentState.snapshot_time.desc())
        .limit(1)
    )
    env_state = result.scalar_one_or_none()

    if env_state is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No current environment state found. Database may not be seeded.",
        )

    return EnvironmentStateSchema.from_orm_state(env_state)
