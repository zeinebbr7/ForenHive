from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from config import get_settings
from models.report import ReportListResponse, ReportMeta, ReportRequest
from services.report_service import get_reports

router = APIRouter(prefix="/api/reports", tags=["reports"])
limiter = Limiter(key_func=get_remote_address)
_SENSITIVE = get_settings().ratelimit_sensitive


@router.post("/generate", response_model=ReportMeta)
@limiter.limit(_SENSITIVE)
async def generate_report(request: Request, req: ReportRequest = Body(...)) -> ReportMeta:
    if req.scope.value == "ip" and not req.ip:
        raise HTTPException(status_code=400, detail="ip required for ip scope")
    if req.scope.value == "session" and not req.session_id:
        raise HTTPException(status_code=400, detail="session_id required for session scope")
    try:
        return await get_reports().generate(req)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"report generation failed: {exc}")


@router.get("", response_model=ReportListResponse)
async def list_reports(limit: int = Query(100, ge=1, le=500)) -> ReportListResponse:
    total, items = await get_reports().list_reports(limit=limit)
    return ReportListResponse(total=total, items=items)


@router.get("/{report_id}/download")
async def download_report(report_id: str):
    svc = get_reports()
    meta = await svc.get_meta(report_id)
    if not meta:
        raise HTTPException(status_code=404, detail="report not found")
    try:
        path = svc.resolve_pdf_path(meta)
    except FileNotFoundError:
        raise HTTPException(status_code=410, detail="report file missing on disk")
    except PermissionError:
        raise HTTPException(status_code=403, detail="report path rejected")
    return FileResponse(
        path=str(path),
        media_type="application/pdf",
        filename=f"{meta.id}.pdf",
        headers={"X-ForenHive-SHA256": meta.sha256},
    )


@router.post("/{report_id}/stix")
async def export_stix(report_id: str):
    bundle = await get_reports().stix_for(report_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="report not found")
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="{report_id}.stix.json"'},
    )
