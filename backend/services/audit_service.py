from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db import session_scope
from models_sql.audit import AuditLog
from models_sql.user import User

log = logging.getLogger(__name__)


async def record(
    *,
    action: str,
    actor: Optional[User] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        async with session_scope() as db:
            db.add(
                AuditLog(
                    actor_id=actor.id if actor else None,
                    actor_email=actor.email if actor else None,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    method=method,
                    path=path,
                    status_code=status_code,
                    ip=ip,
                    user_agent=user_agent,
                    metadata_=metadata or None,
                )
            )
    except Exception as exc:
        # Audit must never break the request.
        log.warning("audit write failed for action=%s: %s", action, exc)


async def list_recent(
    db: AsyncSession,
    limit: int = 100,
    actor_email: Optional[str] = None,
    action: Optional[str] = None,
) -> Tuple[int, List[AuditLog]]:
    q = select(AuditLog)
    c = select(func.count(AuditLog.id))
    if actor_email:
        q = q.where(AuditLog.actor_email == actor_email)
        c = c.where(AuditLog.actor_email == actor_email)
    if action:
        q = q.where(AuditLog.action == action)
        c = c.where(AuditLog.action == action)
    q = q.order_by(AuditLog.timestamp.desc()).limit(limit)
    total = (await db.execute(c)).scalar_one()
    rows = (await db.execute(q)).scalars().all()
    return int(total), list(rows)
