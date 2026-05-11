from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

from apscheduler.schedulers.background import BackgroundScheduler

from fastapi import Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import get_settings
from db import dispose as dispose_db, init_db
from routers import alerts, attacks, audit, auth, chat, forensics, geo, profiling, reports, risk_score, sessions
from services import forensic_runner
from services import audit_service
from services.alert_watcher import get_watcher
from services.auth_service import bootstrap_admin, get_current_user
from services.elasticsearch import get_es

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("forenhive.backend")

settings = get_settings()

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.ratelimit_default])


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("ForenHive backend starting (env=%s)", settings.app_env)

    # Postgres
    try:
        await init_db()
        await bootstrap_admin()
    except Exception as exc:
        log.exception("postgres init failed: %s", exc)

    # Elasticsearch
    es = get_es()
    healthy = await es.ping()
    log.info("Elasticsearch reachable: %s", healthy)
    if healthy:
        try:
            await es.ensure_internal_indices()
        except Exception as exc:
            log.warning("index bootstrap failed: %s", exc)

    # Alert watcher (background task)
    try:
        await get_watcher().start()
    except Exception as exc:
        log.warning("watcher start failed: %s", exc)

    # Forensic engine scheduler (every 6 hours)
    scheduler = BackgroundScheduler()
    scheduler.add_job(forensic_runner.run_forensic_engine, "interval", hours=6)
    scheduler.start()
    log.info("Forensic scheduler started (every 6 h)")

    yield

    scheduler.shutdown(wait=False)

    try:
        await get_watcher().stop()
    except Exception:
        pass
    await es.close()
    await dispose_db()
    log.info("ForenHive backend stopped")


app = FastAPI(
    title="ForenHive Backend",
    version="1.0.0",
    description="Forensic analysis API for the ForenHive honeypot platform",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-ForenHive-SHA256"],
)


_AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_AUDIT_SKIP_PREFIXES = ("/api/alerts/evaluate", "/api/auth/login")


@app.middleware("http")
async def request_middleware(request: Request, call_next):
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

    # Async audit fire-and-forget (POST/PUT/PATCH/DELETE on /api/*)
    path = request.url.path
    if (
        request.method in _AUDITED_METHODS
        and path.startswith("/api/")
        and not any(path.startswith(p) for p in _AUDIT_SKIP_PREFIXES)
    ):
        actor = getattr(request.state, "user", None)
        try:
            await audit_service.record(
                action=f"{request.method.lower()}:{path}",
                actor=actor,
                method=request.method,
                path=path,
                status_code=response.status_code,
                ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
        except Exception:
            pass
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
    return JSONResponse(body, status_code=status_code, media_type="application/problem+json")


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


# ---------- health (public) ----------
@app.get("/health", tags=["meta"])
async def health() -> Dict[str, Any]:
    from sqlalchemy import text as _text
    from db import get_sessionmaker as _gsm

    es_ok = await get_es().ping()

    pg_ok = False
    try:
        async with _gsm()() as _s:
            await _s.execute(_text("SELECT 1"))
        pg_ok = True
    except Exception:
        pass

    return {
        "status": "ok" if (es_ok and pg_ok) else "degraded",
        "elasticsearch": es_ok,
        "postgresql": pg_ok,
        "version": app.version,
        "auth_enabled": not settings.disable_auth,
    }


# ---------- routers ----------
# /api/auth is public (login + refresh). Everything else requires a bearer token
# unless DISABLE_AUTH=true is set (useful for local dev).
app.include_router(auth.router)
app.include_router(chat.router)   # /api/chat — public (auth checked client-side via token)

_protected_deps = [] if settings.disable_auth else [Depends(get_current_user)]

app.include_router(attacks.router, dependencies=_protected_deps)
app.include_router(sessions.router, dependencies=_protected_deps)
app.include_router(geo.router, dependencies=_protected_deps)
app.include_router(alerts.router, dependencies=_protected_deps)
app.include_router(profiling.router, dependencies=_protected_deps)
app.include_router(reports.router, dependencies=_protected_deps)
app.include_router(risk_score.router, dependencies=_protected_deps)
app.include_router(forensics.router, dependencies=_protected_deps)
app.include_router(audit.router)  # audit has its own admin guard


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.app_host,
        port=settings.app_port,
        log_level=settings.log_level,
    )
