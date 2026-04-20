from __future__ import annotations

import ipaddress

from fastapi import APIRouter, HTTPException

from models.report import AttackerProfile
from services.profiler import build_profile

router = APIRouter(prefix="/api/profiling", tags=["profiling"])


@router.get("/{ip}", response_model=AttackerProfile)
async def profile(ip: str) -> AttackerProfile:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    return await build_profile(ip)
