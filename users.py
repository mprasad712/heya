from datetime import datetime, timezone
import secrets
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import and_, distinct, exists, func
from sqlalchemy.orm import aliased
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.sql.expression import SelectOfScalar

from agentcore.api.schemas import UsersResponse, UserReadWithPermissions
from agentcore.api.utils import CurrentActiveUser, DbSession
from agentcore.services.auth.decorators import PermissionChecker
from agentcore.services.auth.permissions import get_permissions_for_role, normalize_role, permission_cache
from agentcore.services.auth.utils import get_password_hash, verify_password
from agentcore.services.auth.soft_delete import soft_delete_user_hierarchy
from agentcore.services.cache.user_cache import UserCacheService
from agentcore.services.database.models.department.model import Department
from agentcore.services.database.models.organization.model import Organization
from agentcore.services.database.models.role.model import Role
from agentcore.services.database.models.user.crud import get_user_by_id, get_user_by_username, update_user
from agentcore.services.database.models.user.model import User, UserCreate, UserRead, UserUpdate
from agentcore.services.database.models.user_department_membership.model import UserDepartmentMembership
from agentcore.services.database.models.user_organization_membership.model import UserOrganizationMembership
from agentcore.services.deps import get_settings_service

router = APIRouter(tags=["Users"], prefix="/users")

ACTIVE_ORG_STATUSES = {"accepted", "active"}
ACTIVE_DEPT_STATUS = "active"


def _strip_or_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _normalize_identity(value: str | None) -> str | None:
    stripped = _strip_or_none(value)
    if not stripped:
        return None
    return stripped.lower() if "@" in stripped else stripped


async def _assignable_roles_for_creator(session: DbSession, creator_role: str) -> list[str]:
    role_rows = (
        await session.exec(
            select(Role).where(Role.is_active.is_(True)).order_by(Role.name)
        )
    ).all()
    global_role_names = [normalize_role(role.name) for role in role_rows]

    if creator_role == "root":
        return [role for role in global_role_names if role == "super_admin"]

    if creator_role == "super_admin":
        return [
            role
            for role in global_role_names
            if role in {"department_admin", "developer", "business_user"}
        ]

    if creator_role == "department_admin":
        return [
            role
            for role in global_role_names
            if role in {"developer", "business_user"}
        ]

    return []


async def _get_role_entity(session: DbSession, role_name: str) -> Role:
    normalized = normalize_role(role_name)
    role = (await session.exec(select(Role).where(Role.name == normalized))).first()
    if not role:
        raise HTTPException(status_code=400, detail=f"Role '{normalized}' is not configured.")
    return role


async def _get_admin_org_ids(session: DbSession, current_user: User) -> set[UUID]:
    if normalize_role(current_user.role) == "root":
        return set((await session.exec(select(Organization.id))).all())
    rows = (
        await session.exec(
            select(UserOrganizationMembership.org_id).where(
                UserOrganizationMembership.user_id == current_user.id,
                UserOrganizationMembership.status.in_(list(ACTIVE_ORG_STATUSES)),
            )
        )
    ).all()
    return set(rows)


async def _get_admin_department_ids(session: DbSession, current_user: User) -> set[UUID]:
    rows = (
        await session.exec(
            select(UserDepartmentMembership.department_id).where(
                UserDepartmentMembership.user_id == current_user.id,
                UserDepartmentMembership.status == ACTIVE_DEPT_STATUS,
            )
        )
    ).all()
    return set(rows)


async def _resolve_creator_org(
    session: DbSession,
    current_user: User,
    organization_name: str | None,
) -> UUID:
    org_ids = await _get_admin_org_ids(session, current_user)
    if not org_ids:
        raise HTTPException(status_code=400, detail="Creator has no organization membership.")

    if len(org_ids) == 1 and not organization_name:
        return next(iter(org_ids))

    if not organization_name:
        raise HTTPException(status_code=400, detail="Organization name is required.")

    org = (
        await session.exec(
            select(Organization).where(
                Organization.id.in_(list(org_ids)),
                Organization.name == organization_name,
            )
        )
    ).first()
    if not org:
        raise HTTPException(status_code=400, detail="Invalid organization name.")
    return org.id


async def _ensure_org_membership(
    session: DbSession,
    *,
    user_id: UUID,
    org_id: UUID,
    role_id: UUID,
    actor_user_id: UUID,
) -> None:
    existing = (
        await session.exec(
            select(UserOrganizationMembership).where(
                UserOrganizationMembership.user_id == user_id,
                UserOrganizationMembership.org_id == org_id,
            )
        )
    ).first()
    if existing:
        existing.role_id = role_id
        existing.status = "active"
        existing.updated_at = datetime.now(timezone.utc)
        existing.accepted_at = existing.accepted_at or datetime.now(timezone.utc)
        session.add(existing)
        return

    session.add(
        UserOrganizationMembership(
            user_id=user_id,
            org_id=org_id,
            status="active",
            role_id=role_id,
            invited_by=actor_user_id,
            accepted_at=datetime.now(timezone.utc),
        )
    )


async def _ensure_department_membership(
    session: DbSession,
    *,
    user_id: UUID,
    org_id: UUID,
    department_id: UUID,
    role_id: UUID,
    actor_user_id: UUID,
) -> None:
    existing = (
        await session.exec(
            select(UserDepartmentMembership).where(
                UserDepartmentMembership.user_id == user_id,
                UserDepartmentMembership.org_id == org_id,
                UserDepartmentMembership.department_id == department_id,
            )
        )
    ).first()
    if existing:
        existing.role_id = role_id
        existing.status = ACTIVE_DEPT_STATUS
        existing.updated_at = datetime.now(timezone.utc)
        existing.assigned_at = existing.assigned_at or datetime.now(timezone.utc)
        session.add(existing)
        return

    session.add(
        UserDepartmentMembership(
            user_id=user_id,
            org_id=org_id,
            department_id=department_id,
            status=ACTIVE_DEPT_STATUS,
            role_id=role_id,
            assigned_by=actor_user_id,
            assigned_at=datetime.now(timezone.utc),
        )
    )


async def _visible_user_ids_for_admin(session: DbSession, current_user: User) -> set[UUID]:
    role = normalize_role(current_user.role)
    if role == "root":
        return set((await session.exec(select(User.id).where(User.id != current_user.id))).all())

    if role == "super_admin":
        org_ids = await _get_admin_org_ids(session, current_user)
        if not org_ids:
            return set()
        rows = (
            await session.exec(
                select(distinct(UserOrganizationMembership.user_id)).where(
                    UserOrganizationMembership.org_id.in_(list(org_ids)),
                    UserOrganizationMembership.status.in_(list(ACTIVE_ORG_STATUSES)),
                )
            )
        ).all()
        return set(rows) - {current_user.id}

    if role == "department_admin":
        dept_ids = await _get_admin_department_ids(session, current_user)
        if not dept_ids:
            return set()
        rows = (
            await session.exec(
                select(distinct(UserDepartmentMembership.user_id)).where(
                    UserDepartmentMembership.department_id.in_(list(dept_ids)),
                    UserDepartmentMembership.status == ACTIVE_DEPT_STATUS,
                )
            )
        ).all()
        return set(rows) - {current_user.id}

    return set()


@router.post("/", response_model=UserRead, status_code=201)
async def add_user(
    user: UserCreate,
    session: DbSession,
    current_user: User = Depends(PermissionChecker(["view_admin_page"])),
) -> User:
    """Add a new user to the database and stitch org/dept memberships by creator role."""
    try:
        username = _normalize_identity(user.username)
        if not username:
            raise HTTPException(status_code=400, detail="Username cannot be empty.")

        email = _normalize_identity(user.email)
        display_name = _strip_or_none(user.display_name)
        department_name = _strip_or_none(user.department_name)
        organization_name = _strip_or_none(user.organization_name)
        organization_description = _strip_or_none(user.organization_description)
        country = _strip_or_none(user.country)

        existing_user = await get_user_by_username(session, username)
        if not existing_user and email:
            existing_user = await get_user_by_username(session, email)
        is_reusing_consumer = bool(
            existing_user and normalize_role(getattr(existing_user, "role", "consumer")) == "consumer"
        )
        if existing_user and not is_reusing_consumer:
            raise HTTPException(status_code=400, detail="This username is unavailable.")

        raw_password = user.password or secrets.token_urlsafe(32)
        if is_reusing_consumer and existing_user:
            new_user = existing_user
            new_user.display_name = display_name or new_user.display_name
            new_user.email = new_user.email or email or username
        else:
            user_payload = user.model_dump()
            user_payload["username"] = username
            user_payload["email"] = email
            user_payload["display_name"] = display_name
            user_payload["department_name"] = department_name
            user_payload["organization_name"] = organization_name
            user_payload["organization_description"] = organization_description
            user_payload["country"] = country
            user_payload["password"] = raw_password
            new_user = User.model_validate(user_payload, from_attributes=True)

        creator_email = getattr(current_user, "username", None)
        creator_role = normalize_role(getattr(current_user, "role", "developer"))
        target_role = normalize_role(user.role)
        assignable_roles = await _assignable_roles_for_creator(session, creator_role)
        new_user.creator_email = creator_email
        new_user.creator_role = creator_role
        new_user.created_by = current_user.id
        new_user.role = target_role

        if target_role not in assignable_roles:
            raise HTTPException(status_code=403, detail="Selected role is not assignable by current user.")

        if creator_role == "root" and not organization_name:
            raise HTTPException(status_code=400, detail="Organization name is required.")

        if creator_role not in {"root", "super_admin", "department_admin"}:
            raise HTTPException(status_code=403, detail="Only admins can create users.")

        new_user.password = get_password_hash(raw_password)
        new_user.is_superuser = new_user.role in {"super_admin", "department_admin", "root"}
        new_user.is_active = get_settings_service().auth_settings.NEW_USER_IS_ACTIVE
        session.add(new_user)
        await session.flush()

        role_entity = await _get_role_entity(session, target_role)

        if creator_role == "root":
            org = Organization(
                name=organization_name,
                description=organization_description,
                status="active",
                owner_user_id=new_user.id,
                created_by=current_user.id,
                updated_by=current_user.id,
            )
            session.add(org)
            await session.flush()
            await _ensure_org_membership(
                session,
                user_id=new_user.id,
                org_id=org.id,
                role_id=role_entity.id,
                actor_user_id=current_user.id,
            )
            root_role = await _get_role_entity(session, "root")
            await _ensure_org_membership(
                session,
                user_id=current_user.id,
                org_id=org.id,
                role_id=root_role.id,
                actor_user_id=current_user.id,
            )

        elif creator_role == "super_admin":
            org_id = await _resolve_creator_org(session, current_user, organization_name)
            await _ensure_org_membership(
                session,
                user_id=new_user.id,
                org_id=org_id,
                role_id=role_entity.id,
                actor_user_id=current_user.id,
            )

            if target_role == "department_admin":
                if not department_name:
                    raise HTTPException(status_code=400, detail="Department name is required for department admins.")
                department = Department(
                    org_id=org_id,
                    name=department_name,
                    admin_user_id=new_user.id,
                    status="active",
                    created_by=current_user.id,
                    updated_by=current_user.id,
                )
                session.add(department)
                await session.flush()
                new_user.department_name = department.name
                new_user.department_admin_email = None
                await _ensure_department_membership(
                    session,
                    user_id=new_user.id,
                    org_id=org_id,
                    department_id=department.id,
                    role_id=role_entity.id,
                    actor_user_id=current_user.id,
                )
            else:
                if target_role not in {"developer", "business_user"}:
                    raise HTTPException(status_code=400, detail="Invalid target role for super admin.")
                if not user.department_id:
                    raise HTTPException(status_code=400, detail="Department is required.")
                department = (
                    await session.exec(
                        select(Department).where(
                            Department.id == user.department_id,
                            Department.org_id == org_id,
                            Department.status == "active",
                        )
                    )
                ).first()
                if not department:
                    raise HTTPException(status_code=400, detail="Invalid department.")
                dept_admin = await session.get(User, department.admin_user_id)
                new_user.department_admin_email = dept_admin.username if dept_admin else None
                new_user.department_name = department.name
                await _ensure_department_membership(
                    session,
                    user_id=new_user.id,
                    org_id=org_id,
                    department_id=department.id,
                    role_id=role_entity.id,
                    actor_user_id=current_user.id,
                )

        elif creator_role == "department_admin":
            creator_membership = (
                await session.exec(
                    select(UserDepartmentMembership).where(
                        UserDepartmentMembership.user_id == current_user.id,
                        UserDepartmentMembership.status == ACTIVE_DEPT_STATUS,
                    )
                )
            ).first()
            if not creator_membership:
                raise HTTPException(status_code=400, detail="Department admin is missing membership mapping.")
            department = await session.get(Department, creator_membership.department_id)
            new_user.department_admin_email = current_user.username
            new_user.department_name = department.name if department else None
            await _ensure_org_membership(
                session,
                user_id=new_user.id,
                org_id=creator_membership.org_id,
                role_id=role_entity.id,
                actor_user_id=current_user.id,
            )
            await _ensure_department_membership(
                session,
                user_id=new_user.id,
                org_id=creator_membership.org_id,
                department_id=creator_membership.department_id,
                role_id=role_entity.id,
                actor_user_id=current_user.id,
            )

        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)

    except HTTPException:
        await session.rollback()
        raise
    except IntegrityError as e:
        await session.rollback()
        raise HTTPException(status_code=400, detail="This username is unavailable.") from e
    except Exception as e:
        await session.rollback()
        raise HTTPException(status_code=500, detail=str(e)) from e

    return new_user


@router.get("/assignable-roles", response_model=list[str])
async def list_assignable_roles(
    session: DbSession,
    current_user: User = Depends(PermissionChecker(["view_admin_page"])),
) -> list[str]:
    creator_role = normalize_role(getattr(current_user, "role", "developer"))
    return await _assignable_roles_for_creator(session, creator_role)


@router.get("/departments")
async def list_visible_departments(
    session: DbSession,
    current_user: User = Depends(PermissionChecker(["view_admin_page"])),
) -> list[dict]:
    current_role = normalize_role(current_user.role)
    if current_role == "root":
        depts = (await session.exec(select(Department).order_by(Department.name.asc()))).all()
    elif current_role == "super_admin":
        org_ids = await _get_admin_org_ids(session, current_user)
        if not org_ids:
            return []
        depts = (
            await session.exec(
                select(Department)
                .where(
                    Department.org_id.in_(list(org_ids)),
                    Department.status == "active",
                )
                .order_by(Department.name.asc())
            )
        ).all()
    elif current_role == "department_admin":
        dept_ids = await _get_admin_department_ids(session, current_user)
        if not dept_ids:
            return []
        depts = (
            await session.exec(
                select(Department)
                .where(
                    Department.id.in_(list(dept_ids)),
                    Department.status == "active",
                )
                .order_by(Department.name.asc())
            )
        ).all()
    else:
        return []

    return [{"id": str(dept.id), "name": dept.name, "org_id": str(dept.org_id)} for dept in depts]


@router.get("/whoami", response_model=UserReadWithPermissions)
async def read_current_user(
    current_user: CurrentActiveUser,
    db: DbSession,
) -> dict:
    """Retrieve the current user's data."""
    settings_service = get_settings_service()
    user_cache = UserCacheService(settings_service)

    try:
        cached_user = await user_cache.get_user(str(current_user.id))
        if not cached_user:
            user = await get_user_by_id(db, current_user.id)
            cached_user = user.model_dump()
            await user_cache.set_user(cached_user)
    except Exception:
        cached_user = current_user.model_dump()

    try:
        if permission_cache:
            user_permissions = await permission_cache.get_permissions_for_role(current_user.role)
        else:
            user_permissions = await get_permissions_for_role(current_user.role)
    except Exception:
        user_permissions = await get_permissions_for_role(current_user.role)

    if not user_permissions:
        user_permissions = await get_permissions_for_role(current_user.role)

    organization_name = (
        await db.exec(
            select(Organization.name)
            .join(
                UserOrganizationMembership,
                UserOrganizationMembership.org_id == Organization.id,
            )
            .where(
                UserOrganizationMembership.user_id == current_user.id,
                UserOrganizationMembership.status.in_(list(ACTIVE_ORG_STATUSES)),
            )
            .order_by(Organization.created_at.asc())
        )
    ).first()

    return {
        **cached_user,
        "permissions": user_permissions,
        "organization_name": organization_name,
    }


@router.get("/", response_model=UsersResponse)
async def read_all_users(
    *,
    skip: int = 0,
    limit: int = 10,
    role: str | None = None,
    q: str | None = None,
    session: DbSession,
    current_admin: User = Depends(PermissionChecker(["view_admin_page"])),
) -> UsersResponse:
    """Retrieve a list of users from the database with hierarchy-aware visibility."""
    visible_user_ids = await _visible_user_ids_for_admin(session, current_admin)
    if not visible_user_ids:
        return UsersResponse(total_count=0, users=[])

    query: SelectOfScalar = select(User).where(
        User.id.in_(list(visible_user_ids)),
        User.deleted_at.is_(None),
    )
    if normalize_role(current_admin.role) != "root":
        query = query.where(User.role != "root")
    else:
        duplicate = aliased(User)
        current_identity = func.lower(func.coalesce(User.email, User.username))
        duplicate_identity = func.lower(func.coalesce(duplicate.email, duplicate.username))
        has_non_consumer_duplicate = exists(
            select(1).where(
                duplicate.id != User.id,
                duplicate_identity == current_identity,
                func.lower(duplicate.role) != "consumer",
            )
        )
        query = query.where(
            ~and_(func.lower(User.role) == "consumer", has_non_consumer_duplicate)
        )
    if role:
        query = query.where(User.role == normalize_role(role))
    if q:
        query = query.where(User.username.ilike(f"%{q}%"))
    query = query.offset(skip).limit(limit)
    users = (await session.exec(query)).fetchall()

    count_query = (
        select(func.count())
        .select_from(User)
        .where(
            User.id.in_(list(visible_user_ids)),
            User.deleted_at.is_(None),
        )
    )
    if normalize_role(current_admin.role) != "root":
        count_query = count_query.where(User.role != "root")
    else:
        duplicate = aliased(User)
        current_identity = func.lower(func.coalesce(User.email, User.username))
        duplicate_identity = func.lower(func.coalesce(duplicate.email, duplicate.username))
        has_non_consumer_duplicate = exists(
            select(1).where(
                duplicate.id != User.id,
                duplicate_identity == current_identity,
                func.lower(duplicate.role) != "consumer",
            )
        )
        count_query = count_query.where(
            ~and_(func.lower(User.role) == "consumer", has_non_consumer_duplicate)
        )
    if role:
        count_query = count_query.where(User.role == normalize_role(role))
    if q:
        count_query = count_query.where(User.username.ilike(f"%{q}%"))
    total_count = (await session.exec(count_query)).first()

    user_ids = [user.id for user in users]
    creator_ids = [user.created_by for user in users if user.created_by]

    org_rows = []
    if user_ids:
        org_rows = (
            await session.exec(
                select(UserOrganizationMembership.user_id, Organization.name)
                .join(Organization, Organization.id == UserOrganizationMembership.org_id)
                .where(
                    UserOrganizationMembership.user_id.in_(user_ids),
                    UserOrganizationMembership.status.in_(list(ACTIVE_ORG_STATUSES)),
                )
            )
        ).all()

    org_map: dict[UUID, str] = {}
    for uid, org_name in org_rows:
        if uid not in org_map:
            org_map[uid] = org_name

    creator_map: dict[UUID, str] = {}
    if creator_ids:
        creator_rows = (
            await session.exec(select(User.id, User.username).where(User.id.in_(list(set(creator_ids)))))
        ).all()
        creator_map = {creator_id: creator_username for creator_id, creator_username in creator_rows}

    return UsersResponse(
        total_count=total_count,
        users=[
            UserRead(
                **user.model_dump(),
                organization_name=org_map.get(user.id),
                created_by_username=creator_map.get(user.created_by) if user.created_by else None,
            )
            for user in users
        ],
    )


@router.patch("/{user_id}", response_model=UserRead)
async def patch_user(
    user_id: UUID,
    user_update: UserUpdate,
    user: CurrentActiveUser,
    session: DbSession,
) -> User:
    """Update an existing user's data."""
    update_password = bool(user_update.password)

    if user.id != user_id:
        visible_user_ids = await _visible_user_ids_for_admin(session, user)
        if user_id not in visible_user_ids:
            raise HTTPException(status_code=403, detail="Permission denied")
        user_permissions = await get_permissions_for_role(user.role)
        if "view_admin_page" not in user_permissions:
            raise HTTPException(status_code=403, detail="Permission denied")
    if update_password:
        if not user.is_superuser:
            raise HTTPException(status_code=400, detail="You can't change your password here")
        user_update.password = get_password_hash(user_update.password)
    if user_update.role:
        user_update.role = normalize_role(user_update.role)
        user_update.is_superuser = user_update.role in {"super_admin", "department_admin", "root"}

    if user_db := await get_user_by_id(session, user_id):
        if not update_password:
            user_update.password = user_db.password
        return await update_user(user_db, user_update, session)
    raise HTTPException(status_code=404, detail="User not found")


@router.patch("/{user_id}/reset-password", response_model=UserRead)
async def reset_password(
    user_id: UUID,
    user_update: UserUpdate,
    user: CurrentActiveUser,
    session: DbSession,
) -> User:
    """Reset a user's password."""
    if user_id != user.id:
        raise HTTPException(status_code=400, detail="You can't change another user's password")

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if verify_password(user_update.password, user.password):
        raise HTTPException(status_code=400, detail="You can't use your current password")
    user.password = get_password_hash(user_update.password)
    await session.commit()
    await session.refresh(user)
    return user


@router.delete("/{user_id}")
async def delete_user(
    user_id: UUID,
    session: DbSession,
    current_user: User = Depends(PermissionChecker(["view_admin_page"])),
) -> dict:
    """Delete a user from the database."""
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="You can't delete your own user account")

    user_db = (
        await session.exec(
            select(User).where(
                User.id == user_id,
                User.deleted_at.is_(None),
            )
        )
    ).first()
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        current_role = normalize_role(current_user.role)
        if current_role != "root":
            if user_db.created_by != current_user.id:
                raise HTTPException(status_code=403, detail="You can delete only users you created.")
            visible_user_ids = await _visible_user_ids_for_admin(session, current_user)
            if user_id not in visible_user_ids:
                raise HTTPException(status_code=403, detail="Permission denied")
        if normalize_role(user_db.role) == "root":
            raise HTTPException(status_code=403, detail="Root users cannot be deleted.")
        deleted_count, _ = await soft_delete_user_hierarchy(
            session,
            user_id,
            actor_user_id=current_user.id,
        )
        if deleted_count == 0:
            raise HTTPException(status_code=409, detail="No eligible users found to delete.")
        await session.commit()
    except HTTPException:
        await session.rollback()
        raise
    except IntegrityError as e:
        await session.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Could not soft delete user due to database constraints."
            ),
        ) from e

    if deleted_count == 1:
        return {"detail": "User deleted."}
    return {
        "detail": f"User deleted with hierarchy. Total users deleted: {deleted_count}.",
    }
