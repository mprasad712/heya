from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import distinct, update
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from agentcore.services.auth.invalidation import invalidate_user_auth
from agentcore.services.auth.permissions import normalize_role
from agentcore.services.database.models.department.model import Department, DeptStatusEnum
from agentcore.services.database.models.organization.model import Organization, OrgStatusEnum
from agentcore.services.database.models.user.model import User
from agentcore.services.database.models.user_department_membership.model import UserDepartmentMembership
from agentcore.services.database.models.user_organization_membership.model import UserOrganizationMembership

ACTIVE_ORG_MEMBERSHIP_STATUSES = {"accepted", "active"}
ACTIVE_DEPT_MEMBERSHIP_STATUS = "active"


async def _collect_cascade_user_ids(db: AsyncSession, root_user_id: UUID) -> set[UUID]:
    selected: set[UUID] = set()
    pending: list[UUID] = [root_user_id]

    while pending:
        user_id = pending.pop()
        if user_id in selected:
            continue
        selected.add(user_id)

        child_user_ids = (
            await db.exec(
                select(User.id).where(
                    User.created_by == user_id,
                    User.deleted_at.is_(None),
                )
            )
        ).all()
        for child_user_id in child_user_ids:
            if child_user_id not in selected:
                pending.append(child_user_id)

        department_ids = (
            await db.exec(
                select(Department.id).where(
                    Department.admin_user_id == user_id,
                    Department.status == DeptStatusEnum.ACTIVE,
                )
            )
        ).all()
        if department_ids:
            member_user_ids = (
                await db.exec(
                    select(distinct(UserDepartmentMembership.user_id)).where(
                        UserDepartmentMembership.department_id.in_(list(department_ids)),
                        UserDepartmentMembership.status == ACTIVE_DEPT_MEMBERSHIP_STATUS,
                    )
                )
            ).all()
            for member_user_id in member_user_ids:
                if member_user_id not in selected:
                    pending.append(member_user_id)

        org_ids = (
            await db.exec(
                select(Organization.id).where(
                    Organization.owner_user_id == user_id,
                    Organization.status == OrgStatusEnum.ACTIVE,
                )
            )
        ).all()
        if org_ids:
            org_member_user_ids = (
                await db.exec(
                    select(distinct(UserOrganizationMembership.user_id)).where(
                        UserOrganizationMembership.org_id.in_(list(org_ids)),
                        UserOrganizationMembership.status.in_(list(ACTIVE_ORG_MEMBERSHIP_STATUSES)),
                    )
                )
            ).all()
            for org_member_user_id in org_member_user_ids:
                if org_member_user_id not in selected:
                    pending.append(org_member_user_id)

    return selected


async def soft_delete_user_hierarchy(
    db: AsyncSession,
    target_user_id: UUID,
    *,
    actor_user_id: UUID | None = None,
) -> tuple[int, list[UUID]]:
    now = datetime.now(timezone.utc)
    cascade_ids = await _collect_cascade_user_ids(db, target_user_id)
    if not cascade_ids:
        return 0, []

    users = (
        await db.exec(
            select(User).where(
                User.id.in_(list(cascade_ids)),
                User.deleted_at.is_(None),
            )
        )
    ).all()

    deleted_ids: list[UUID] = []
    for user in users:
        if normalize_role(user.role) == "root":
            continue
        if actor_user_id and user.id == actor_user_id:
            continue

        await invalidate_user_auth(
            user.id,
            email=user.email or user.username,
            entra_object_id=user.entra_object_id,
        )
        user.is_active = False
        user.deleted_at = now
        user.updated_at = now
        db.add(user)
        deleted_ids.append(user.id)

    if not deleted_ids:
        return 0, []

    await db.exec(
        update(UserOrganizationMembership)
        .where(UserOrganizationMembership.user_id.in_(deleted_ids))
        .values(status="inactive", updated_at=now)
    )
    await db.exec(
        update(UserDepartmentMembership)
        .where(UserDepartmentMembership.user_id.in_(deleted_ids))
        .values(status="inactive", updated_at=now)
    )
    await db.exec(
        update(Department)
        .where(
            Department.admin_user_id.in_(deleted_ids),
            Department.status == DeptStatusEnum.ACTIVE,
        )
        .values(status=DeptStatusEnum.ARCHIVED, updated_at=now, updated_by=actor_user_id)
    )
    await db.exec(
        update(Organization)
        .where(
            Organization.owner_user_id.in_(deleted_ids),
            Organization.status == OrgStatusEnum.ACTIVE,
        )
        .values(status=OrgStatusEnum.SUSPENDED, updated_at=now, updated_by=actor_user_id)
    )

    return len(deleted_ids), deleted_ids
