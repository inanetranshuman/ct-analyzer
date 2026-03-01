from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status
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


async def require_api_key(request: Request, settings: Settings) -> None:
    if has_valid_api_key(settings, _extract_api_key(dict(request.headers))):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
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
