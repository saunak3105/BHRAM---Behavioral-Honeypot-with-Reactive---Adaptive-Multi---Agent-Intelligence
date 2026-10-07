"""
BHRAM API — Files Routes
GET /api/v1/files — list all decoy files
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import DecoyFile
from app.schemas import FileListResponse, DecoyFileSchema

router = APIRouter(prefix="/api/v1", tags=["Files"])


@router.get(
    "/files",
    response_model=FileListResponse,
    summary="List all decoy/bait files",
    description=(
        "Returns all decoy files deployed in the BHRAM deception environment. "
        "Bait level (1-5) indicates the attractiveness/sensitivity of the file. "
        "File content is entirely fictional and contains no real data. "
        "The orchestrator (Part 2) will use this endpoint to manage the decoy file surface."
    ),
)
async def list_files(
    active_only: bool = Query(True, description="Return only active (deployed) decoy files"),
    min_bait_level: int = Query(1, ge=1, le=5, description="Minimum bait level filter"),
    db: AsyncSession = Depends(get_db),
) -> FileListResponse:
    query = select(DecoyFile).order_by(DecoyFile.bait_level.desc(), DecoyFile.filename)

    if active_only:
        query = query.where(DecoyFile.is_active == True)
    if min_bait_level > 1:
        query = query.where(DecoyFile.bait_level >= min_bait_level)

    result = await db.execute(query)
    files = result.scalars().all()

    return FileListResponse(
        total=len(files),
        files=[DecoyFileSchema.model_validate(f) for f in files],
    )
