from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings
from db import get_session, session_scope
from models_sql.user import User, UserRole

log = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(password, hashed)
    except Exception:
        return False


def _encode(sub: str, kind: str, ttl: timedelta, **claims) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "typ": kind,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        **claims,
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def create_access_token(user: User) -> str:
    s = get_settings()
    return _encode(
        str(user.id),
        "access",
        timedelta(minutes=s.jwt_access_ttl_minutes),
        email=user.email,
        role=user.role.value,
    )


def create_refresh_token(user: User) -> str:
    s = get_settings()
    return _encode(
        str(user.id),
        "refresh",
        timedelta(days=s.jwt_refresh_ttl_days),
    )


def decode_token(token: str) -> dict:
    s = get_settings()
    try:
        return jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")


async def authenticate(db: AsyncSession, email: str, password: str) -> Optional[User]:
    res = await db.execute(select(User).where(User.email == email.lower()))
    user = res.scalar_one_or_none()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    return user


async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return None
    res = await db.execute(select(User).where(User.id == uid))
    return res.scalar_one_or_none()


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_session),
) -> Optional[User]:
<<<<<<< HEAD
<<<<<<< HEAD
    """Resolve the current user from the bearer token.

    When `disable_auth=True`, anonymous access is allowed (returns None) but a
    supplied valid token is still resolved — otherwise routes like /auth/me
    that need the user identity break for legitimate authenticated callers.
    """
    if not token:
        if get_settings().disable_auth:
            return None
        raise HTTPException(status_code=401, detail="missing bearer token")
    try:
        payload = decode_token(token)
    except HTTPException:
        if get_settings().disable_auth:
            return None
        raise
    if payload.get("typ") != "access":
        if get_settings().disable_auth:
            return None
        raise HTTPException(status_code=401, detail="wrong token type")
    user = await get_user_by_id(db, payload.get("sub", ""))
    if not user or not user.is_active:
        if get_settings().disable_auth:
            return None
=======
=======
>>>>>>> ismail
    if get_settings().disable_auth:
        return None
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")
    payload = decode_token(token)
    if payload.get("typ") != "access":
        raise HTTPException(status_code=401, detail="wrong token type")
    user = await get_user_by_id(db, payload.get("sub", ""))
    if not user or not user.is_active:
<<<<<<< HEAD
>>>>>>> ismail
=======
>>>>>>> ismail
        raise HTTPException(status_code=401, detail="user disabled or missing")
    request.state.user = user
    return user


def require_role(*allowed: UserRole):
    async def _dep(user: User | None = Depends(get_current_user)) -> User | None:
        if get_settings().disable_auth:
            return None
        if user is None:
            raise HTTPException(status_code=401)
        if allowed and user.role not in allowed:
            raise HTTPException(status_code=403, detail="insufficient role")
        return user
    return _dep


async def bootstrap_admin() -> None:
    s = get_settings()
    async with session_scope() as db:
        res = await db.execute(select(User).where(User.email == s.bootstrap_admin_email.lower()))
        if res.scalar_one_or_none():
            return
        admin = User(
            email=s.bootstrap_admin_email.lower(),
            full_name="ForenHive Admin",
            password_hash=hash_password(s.bootstrap_admin_password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(admin)
    log.info("bootstrapped admin user %s", s.bootstrap_admin_email)
