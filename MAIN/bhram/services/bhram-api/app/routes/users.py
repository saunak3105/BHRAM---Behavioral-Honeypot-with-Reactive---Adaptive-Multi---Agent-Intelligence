"""
BHRAM API — Users Routes
GET /api/v1/users — list all fake company users
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import User
from app.schemas import UserListResponse, UserSchema

router = APIRouter(prefix="/api/v1", tags=["Users"])


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all deception environment users",
    description=(
        "Returns all fictional users registered in the BHRAM deception environment. "
        "These users exist as bait accounts across SSH, web portal, and file system surfaces. "
        "All user data is entirely fictional."
    ),
)
async def list_users(
    department: Optional[str] = Query(None, description="Filter by department name"),
    role: Optional[str] = Query(None, description="Filter by user role"),
    ssh_enabled: Optional[bool] = Query(None, description="Filter SSH-enabled users only"),
    db: AsyncSession = Depends(get_db),
) -> UserListResponse:
    query = select(User).order_by(User.username)

    if department:
        query = query.where(User.department.ilike(f"%{department}%"))
    if role:
        query = query.where(User.role == role)
    if ssh_enabled is not None:
        query = query.where(User.ssh_enabled == ssh_enabled)

    result = await db.execute(query)
    users = result.scalars().all()

    return UserListResponse(
        total=len(users),
        users=[UserSchema.model_validate(u) for u in users],
    )
