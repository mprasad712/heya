from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from loguru import logger
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from sqlalchemy.orm.attributes import flag_modified
from sqlmodel import or_, select
from sqlmodel.ext.asyncio.session import AsyncSession

from agentcore.services.auth.permissions import normalize_role
from agentcore.services.database.models.user.model import User, UserUpdate


def _role_priority(role: str | None) -> int:
    normalized = normalize_role(role or "consumer")
    priorities = {
        "root": 500,
        "super_admin": 400,
        "department_admin": 300,
        "developer": 200,
        "business_user": 200,
        "consumer": 100,
    }
    return priorities.get(normalized, 0)


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    identity = (username or "").strip()
    if not identity:
        return None
    lowered = identity.lower()
    stmt = select(User).where(
        User.deleted_at.is_(None),
        or_(
            func.lower(User.username) == lowered,
            func.lower(User.email) == lowered,
        )
    )
    candidates = (await db.exec(stmt)).all()
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    # Prefer the strongest role row when legacy duplicate identities exist.
    candidates.sort(
        key=lambda user: (
            _role_priority(getattr(user, "role", None)),
            1 if getattr(user, "is_superuser", False) else 0,
            1 if getattr(user, "created_by", None) else 0,
            getattr(user, "updated_at", None) or getattr(user, "create_at", None),
        ),
        reverse=True,
    )
    return candidates[0]


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User | None:
    if isinstance(user_id, str):
        user_id = UUID(user_id)
    stmt = select(User).where(User.id == user_id, User.deleted_at.is_(None))
    return (await db.exec(stmt)).first()


async def update_user(user_db: User | None, user: UserUpdate, db: AsyncSession) -> User:
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")

    # user_db_by_username = get_user_by_username(db, user.username)
    # if user_db_by_username and user_db_by_username.id != user_id:
    #     raise HTTPException(status_code=409, detail="Username already exists")

    user_data = user.model_dump(exclude_unset=True)
    changed = False
    for attr, value in user_data.items():
        if hasattr(user_db, attr) and value is not None:
            setattr(user_db, attr, value)
            changed = True

    if not changed:
        raise HTTPException(status_code=status.HTTP_304_NOT_MODIFIED, detail="Nothing to update")

    user_db.updated_at = datetime.now(timezone.utc)
    flag_modified(user_db, "updated_at")

    try:
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(e)) from e

    return user_db


async def update_user_last_login_at(user_id: UUID, db: AsyncSession):
    try:
        user_data = UserUpdate(last_login_at=datetime.now(timezone.utc))
        user = await get_user_by_id(db, user_id)
        return await update_user(user, user_data, db)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error updating user last login at: {e!s}")
