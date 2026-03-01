from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from ct_analyzer.config import Settings


def _extract_api_key(headers: dict[str, str]) -> str | None:
    api_key = headers.get("x-api-key")
    if api_key:
        return api_key
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def has_valid_api_key(settings: Settings, candidate: str | None) -> bool:
    if not settings.auth.enabled:
        return True
    if not candidate:
        return False
    return any(hmac.compare_digest(candidate, configured) for configured in settings.auth.api_keys)


def is_ui_session_authenticated(request: Request, settings: Settings) -> bool:
    if not settings.auth.enabled:
        return True
    session = getattr(request, "session", None) or {}
    authenticated = session.get("authenticated") is True
    username = session.get("username")
    return authenticated and username == settings.session.admin_username


async def require_api_key(request: Request, settings: Settings) -> None:
    if has_valid_api_key(settings, _extract_api_key(dict(request.headers))):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_api_key_or_session(request: Request, settings: Settings) -> None:
    if has_valid_api_key(settings, _extract_api_key(dict(request.headers))):
        return
    if is_ui_session_authenticated(request, settings):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_ui_session(request: Request, settings: Settings) -> None:
    if is_ui_session_authenticated(request, settings):
        return
    raise HTTPException(
        status_code=status.HTTP_303_SEE_OTHER,
        detail="Login required",
        headers={"Location": "/login"},
    )


class APIKeyASGIMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.settings.auth.enabled:
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        if has_valid_api_key(self.settings, _extract_api_key(headers)):
            await self.app(scope, receive, send)
            return

        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"www-authenticate", b"Bearer"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"Authentication required"})


class SessionCookieSecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.url.scheme == "https" and self.settings.session.https_only:
            cookie_headers = response.headers.getlist("set-cookie")
            updated_headers: list[str] = []
            for header in cookie_headers:
                if header.startswith(f"{self.settings.session.cookie_name}=") and "secure" not in header.lower():
                    updated_headers.append(f"{header}; Secure")
                else:
                    updated_headers.append(header)
            if updated_headers:
                del response.headers["set-cookie"]
                for header in updated_headers:
                    response.headers.append("set-cookie", header)
        return response
