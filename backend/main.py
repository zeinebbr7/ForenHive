from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import get_settings
from routers import alerts, attacks, geo, profiling, reports, sessions
from services.elasticsearch import get_es

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("forenhive.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    log.info("ForenHive backend starting (env=%s)", settings.app_env)
    es = get_es()
    healthy = await es.ping()
    log.info("Elasticsearch reachable: %s", healthy)
    if healthy:
        try:
            await es.ensure_internal_indices()
        except Exception as exc:
            log.warning("index bootstrap failed: %s", exc)
    yield
    await es.close()
    log.info("ForenHive backend stopped")


app = FastAPI(
    title="ForenHive Backend",
    version="1.0.0",
    description="Forensic analysis API for the ForenHive honeypot platform",
    lifespan=lifespan,
)

settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-ForenHive-SHA256"],
)


@app.middleware("http")
async def request_logging(request: Request, call_next):
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        duration = (time.perf_counter() - start) * 1000
        log.exception(
            "req_id=%s method=%s path=%s duration_ms=%.1f error=%s",
            req_id, request.method, request.url.path, duration, exc,
        )
        raise
    duration = (time.perf_counter() - start) * 1000
    response.headers["X-Request-ID"] = req_id
    log.info(
        "req_id=%s method=%s path=%s status=%s duration_ms=%.1f",
        req_id, request.method, request.url.path, response.status_code, duration,
    )
    return response


# ---------- RFC 7807 problem+json error handlers ----------
def _problem(
    status_code: int,
    title: str,
    detail: Any = None,
    type_: str = "about:blank",
    instance: str | None = None,
    extra: Dict[str, Any] | None = None,
) -> JSONResponse:
    body = {
        "type": type_,
        "title": title,
        "status": status_code,
        "detail": detail if isinstance(detail, str) else str(detail) if detail is not None else title,
    }
    if instance:
        body["instance"] = instance
    if extra:
        body.update(extra)
    return JSONResponse(
        body,
        status_code=status_code,
        media_type="application/problem+json",
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return _problem(
        status_code=exc.status_code,
        title=exc.detail if isinstance(exc.detail, str) else "HTTP error",
        detail=exc.detail,
        instance=str(request.url.path),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return _problem(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        title="Validation failed",
        detail="One or more request fields are invalid",
        instance=str(request.url.path),
        extra={"errors": exc.errors()},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log.exception("unhandled error on %s", request.url.path)
    return _problem(
        status_code=500,
        title="Internal Server Error",
        detail=str(exc),
        instance=str(request.url.path),
    )


# ---------- health ----------
@app.get("/health", tags=["meta"])
async def health() -> Dict[str, Any]:
    es_ok = await get_es().ping()
    return {
        "status": "ok" if es_ok else "degraded",
        "elasticsearch": es_ok,
        "version": app.version,
    }


# ---------- routers ----------
app.include_router(attacks.router)
app.include_router(sessions.router)
app.include_router(geo.router)
app.include_router(alerts.router)
app.include_router(profiling.router)
app.include_router(reports.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.app_host,
        port=settings.app_port,
        log_level=settings.log_level,
    )
