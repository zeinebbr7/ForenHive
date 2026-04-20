from __future__ import annotations

from fastapi import APIRouter, Query

from services.elasticsearch import get_es

router = APIRouter(prefix="/api/geo", tags=["geo"])


@router.get("/breakdown")
async def geo_breakdown(top: int = Query(25, ge=1, le=200)):
    return {"top": top, "countries": await get_es().country_breakdown(top=top)}


@router.get("/honeypot-split")
async def honeypot_split():
    return {"split": await get_es().honeypot_split()}
