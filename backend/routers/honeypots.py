from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException

from models_sql.user import User, UserRole
from services.auth_service import require_role

router = APIRouter(prefix="/api/honeypots", tags=["honeypots"])

ALLOWED = {
    "cowrie": "forenhive-cowrie",
    "dionaea": "forenhive-dionaea",
    "galah": "forenhive-galah",
}


def _client():
    try:
        import docker
    except Exception as e:
        raise HTTPException(500, f"docker SDK unavailable: {e}")
    try:
        return docker.from_env()
    except Exception as e:
        raise HTTPException(500, f"docker socket unreachable: {e}")


def _resolve(name: str) -> str:
    if name not in ALLOWED:
        raise HTTPException(404, f"unknown honeypot '{name}'")
    return ALLOWED[name]


@router.get("/status")
async def status(_admin: User = Depends(require_role(UserRole.ADMIN))) -> Dict[str, str]:
    cli = _client()
    out: Dict[str, str] = {}
    for hp, cname in ALLOWED.items():
        try:
            c = cli.containers.get(cname)
            out[hp] = c.status
        except Exception:
            out[hp] = "missing"
    return out


@router.post("/{name}/start")
async def start(name: str, admin: User = Depends(require_role(UserRole.ADMIN))) -> Dict[str, str]:
    cname = _resolve(name)
    cli = _client()
    try:
        c = cli.containers.get(cname)
        c.start()
        return {"honeypot": name, "container": cname, "status": c.status, "actor": admin.email}
    except Exception as e:
        raise HTTPException(500, f"start failed: {e}")


@router.post("/{name}/stop")
async def stop(name: str, admin: User = Depends(require_role(UserRole.ADMIN))) -> Dict[str, str]:
    cname = _resolve(name)
    cli = _client()
    try:
        c = cli.containers.get(cname)
        c.stop(timeout=10)
        return {"honeypot": name, "container": cname, "status": c.status, "actor": admin.email}
    except Exception as e:
        raise HTTPException(500, f"stop failed: {e}")
