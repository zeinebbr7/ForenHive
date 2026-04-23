from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from db import get_session
from models_sql.user import User, UserRole
from services import audit_service
from services.auth_service import require_role

router = APIRouter(prefix="/api/audit", tags=["audit"])


class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    actor_email: Optional[str] = None
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    ip: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AuditListResponse(BaseModel):
    total: int
    items: List[AuditEntry]


@router.get("", response_model=AuditListResponse)
async def list_audit(
    limit: int = Query(100, ge=1, le=1000),
    actor_email: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    _admin: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_session),
) -> AuditListResponse:
    total, rows = await audit_service.list_recent(
        db, limit=limit, actor_email=actor_email, action=action
    )
    return AuditListResponse(
        total=total,
        items=[
            AuditEntry(
                id=str(r.id),
                timestamp=r.timestamp,
                actor_email=r.actor_email,
                action=r.action,
                target_type=r.target_type,
                target_id=r.target_id,
                method=r.method,
                path=r.path,
                status_code=r.status_code,
                ip=r.ip,
                metadata=r.metadata_,
            )
            for r in rows
        ],
    )
