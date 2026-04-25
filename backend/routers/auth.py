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
    email: EmailStr
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
async def me(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
) -> UserOut:
    if user is None:
        # DISABLE_AUTH mode: fall back to the bootstrap admin so the UI has a user to display
        if get_settings().disable_auth:
            s = get_settings()
            res = await db.execute(select(User).where(User.email == s.bootstrap_admin_email.lower()))
            admin = res.scalar_one_or_none()
            if admin:
                return UserOut.from_orm_user(admin)
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
