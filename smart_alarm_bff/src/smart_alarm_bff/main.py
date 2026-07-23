"""HTTP process entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager
import secrets
import time

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
import uvicorn

from . import __version__
from .config import ConfigError, load_settings
from .infrastructure import Infrastructure
from .directory_routes import mount_directory_routes
from .device_routes import mount_device_routes
from .write_routes import mount_write_routes
from .session import SessionError, SessionService, parse_bearer


REQUESTS = Counter("smart_alarm_http_requests_total", "HTTP requests", ("method", "path", "status"))
LATENCY = Histogram("smart_alarm_http_request_duration_seconds", "HTTP request latency", ("method", "path"))


def create_app() -> FastAPI:
    settings = load_settings()
    infrastructure = Infrastructure(settings)
    sessions = SessionService(infrastructure.thingsboard, settings.session_key, cookie_name=settings.session_cookie_name)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        await infrastructure.close()

    app = FastAPI(
        title="Smart Alarm BFF",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.infrastructure = infrastructure
    app.state.sessions = sessions
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Idempotency-Key", "X-CSRF-Token", "X-Request-ID"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        started = time.monotonic()
        request_id = request.headers.get("X-Request-ID", "")
        if not request_id or len(request_id) > 128 or any(ord(char) < 33 or ord(char) > 126 for char in request_id):
            request_id = secrets.token_hex(16)
        try:
            response = await call_next(request)
        except Exception:
            response = JSONResponse(status_code=500, content={"error": {"code": "internal_error", "message": "internal server error"}})
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        path = request.scope.get("route").path if request.scope.get("route") is not None else "unmatched"
        REQUESTS.labels(request.method, path, str(response.status_code)).inc()
        LATENCY.labels(request.method, path).observe(time.monotonic() - started)
        return response

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, object]:
        return {
            "status": "ok",
            "service": "smart-alarm-bff",
            "version": __version__,
            "environment": settings.environment,
            "deploymentCommit": settings.deployment_commit,
        }

    @app.get("/ready", include_in_schema=False)
    async def ready() -> Response:
        payload = await infrastructure.readiness()
        return JSONResponse(status_code=200 if payload["ready"] else 503, content=payload)

    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: Request) -> Response:
        if request.client is None or request.client.host not in {"127.0.0.1", "::1"}:
            return JSONResponse(status_code=404, content={"error": {"code": "not_found", "message": "endpoint not found"}})
        return PlainTextResponse(generate_latest().decode("utf-8"), media_type=CONTENT_TYPE_LATEST)

    def session_error(exc: SessionError) -> JSONResponse:
        # Do not disclose whether the platform identity, local mapping or scope failed.
        message = "authentication failed" if exc.status_code != 403 else "request is not authorized"
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": message}})

    @app.post("/api/v1/session")
    async def create_session(request: Request, response: Response) -> Response:
        try:
            platform_token = parse_bearer(request.headers.get("Authorization"))
            context, csrf_token = await sessions.create(await infrastructure.database(), platform_token)
        except SessionError as exc:
            return session_error(exc)
        response.set_cookie(
            settings.session_cookie_name,
            context.session_token,
            max_age=8 * 60 * 60,
            httponly=True,
            secure=settings.secure_cookies,
            samesite="lax",
            path="/",
        )
        return {"csrfToken": csrf_token}

    @app.get("/api/v1/session")
    async def get_session(request: Request) -> Response:
        try:
            context = await sessions.resolve(
                await infrastructure.database(), request.cookies.get(settings.session_cookie_name)
            )
        except SessionError as exc:
            return session_error(exc)
        return context.principal.public_summary()

    @app.post("/api/v1/session/logout")
    async def logout_session(request: Request, response: Response) -> Response:
        try:
            await sessions.revoke(
                await infrastructure.database(),
                request.cookies.get(settings.session_cookie_name),
                request.headers.get("X-CSRF-Token"),
            )
        except SessionError as exc:
            return session_error(exc)
        response.delete_cookie(settings.session_cookie_name, path="/", secure=settings.secure_cookies, samesite="lax")
        return {"status": "ok"}

    mount_directory_routes(app, sessions, infrastructure.database)
    mount_write_routes(app, sessions, infrastructure.database, infrastructure.thingsboard)
    mount_device_routes(app, sessions, infrastructure.database)

    return app


def run() -> None:
    try:
        settings = load_settings()
    except ConfigError as exc:
        raise SystemExit(f"invalid runtime configuration: {exc}") from None
    uvicorn.run(
        create_app,
        factory=True,
        host=settings.bind_host,
        port=9081,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        server_header=False,
        access_log=False,
        timeout_keep_alive=5,
    )


if __name__ == "__main__":
    run()
