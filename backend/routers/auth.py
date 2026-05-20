from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings
from db import get_session
from models_sql.user import User, UserRole
from services import audit_service
from services.auth_service import (
    authenticate,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    get_user_by_id,
    hash_password,
    require_role,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    @classmethod
    def from_orm_user(cls, u: User) -> "UserOut":
        return cls(
            id=str(u.id),
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
        )


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login", response_model=TokenPair)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_session),
) -> TokenPair:
    user = await authenticate(db, form.username, form.password)
    if not user:
        await audit_service.record(
            action="auth.login_failed",
            path=str(request.url.path),
            method=request.method,
            ip=request.client.host if request.client else None,
            metadata={"email": form.username},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    await audit_service.record(
        action="auth.login",
        actor=user,
        path=str(request.url.path),
        method=request.method,
        ip=request.client.host if request.client else None,
    )
    s = get_settings()
    return TokenPair(
        access_token=create_access_token(user),
        refresh_token=create_refresh_token(user),
        expires_in=s.jwt_access_ttl_minutes * 60,
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_session),
) -> TokenPair:
    payload = decode_token(body.refresh_token)
    if payload.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="expected refresh token")
    user = await get_user_by_id(db, payload.get("sub", ""))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="user disabled or missing")
    s = get_settings()
    return TokenPair(
        access_token=create_access_token(user),
        refresh_token=create_refresh_token(user),
        expires_in=s.jwt_access_ttl_minutes * 60,
    )


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    if user is None:
        raise HTTPException(status_code=401)
    return UserOut.from_orm_user(user)


@router.get("/users", response_model=list[UserOut])
async def list_users(
    _admin: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
) -> list[UserOut]:
    rows = (await db.execute(select(User).order_by(User.created_at))).scalars().all()
    return [UserOut.from_orm_user(u) for u in rows]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    request: Request,
    admin: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
) -> UserOut:
    existing = (await db.execute(select(User).where(User.email == body.email.lower()))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="email already registered")
    user = User(
        email=body.email.lower(),
        full_name=body.full_name,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await audit_service.record(
        action="user.create",
        actor=admin,
        target_type="user",
        target_id=str(user.id),
        path=str(request.url.path),
        method=request.method,
        ip=request.client.host if request.client else None,
        metadata={"email": user.email, "role": user.role.value},
    )
    return UserOut.from_orm_user(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str,
    body: UserUpdate,
    request: Request,
    admin: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
) -> UserOut:
    target = await get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="user not found")

    changes: dict = {}
    if body.email is not None and body.email.lower() != target.email:
        exists = (await db.execute(select(User).where(User.email == body.email.lower()))).scalar_one_or_none()
        if exists and str(exists.id) != str(target.id):
            raise HTTPException(status_code=409, detail="email already registered")
        target.email = body.email.lower()
        changes["email"] = target.email
    if body.full_name is not None:
        target.full_name = body.full_name or None
        changes["full_name"] = target.full_name
    if body.password:
        target.password_hash = hash_password(body.password)
        changes["password"] = "***"
    if body.role is not None:
        if str(target.id) == str(admin.id) and body.role != UserRole.ADMIN:
            raise HTTPException(status_code=400, detail="cannot demote yourself")
        target.role = body.role
        changes["role"] = body.role.value
    if body.is_active is not None:
        if str(target.id) == str(admin.id) and not body.is_active:
            raise HTTPException(status_code=400, detail="cannot disable yourself")
        target.is_active = body.is_active
        changes["is_active"] = body.is_active

    await db.commit()
    await db.refresh(target)
    await audit_service.record(
        action="user.update",
        actor=admin,
        target_type="user",
        target_id=str(target.id),
        path=str(request.url.path),
        method=request.method,
        ip=request.client.host if request.client else None,
        metadata=changes,
    )
    return UserOut.from_orm_user(target)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    request: Request,
    admin: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
) -> None:
    target = await get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="user not found")
    if str(target.id) == str(admin.id):
        raise HTTPException(status_code=400, detail="cannot delete yourself")
    if target.role == UserRole.ADMIN:
        remaining = (await db.execute(
            select(User).where(User.role == UserRole.ADMIN, User.is_active == True, User.id != target.id)  # noqa: E712
        )).scalars().all()
        if not remaining:
            raise HTTPException(status_code=400, detail="cannot delete the last active admin")
    email = target.email
    await db.delete(target)
    await db.commit()
    await audit_service.record(
        action="user.delete",
        actor=admin,
        target_type="user",
        target_id=user_id,
        path=str(request.url.path),
        method=request.method,
        ip=request.client.host if request.client else None,
        metadata={"email": email},
    )
