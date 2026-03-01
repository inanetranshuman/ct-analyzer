from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from ct_analyzer.config import Settings
from ct_analyzer.security import is_ui_session_authenticated

UI_DIR = Path(__file__).resolve().parent.parent / "ui"


def build_ui_router(settings: Settings) -> APIRouter:
    router = APIRouter(include_in_schema=False)

    @router.get("/")
    async def index(request: Request) -> FileResponse | RedirectResponse:
        if settings.auth.enabled and not is_ui_session_authenticated(request, settings):
            return RedirectResponse(url="/login", status_code=303)
        return FileResponse(UI_DIR / "index.html")

    @router.get("/login")
    async def login_page(request: Request) -> FileResponse | RedirectResponse:
        if is_ui_session_authenticated(request, settings):
            return RedirectResponse(url="/", status_code=303)
        return FileResponse(UI_DIR / "login.html")

    @router.post("/login")
    async def login(request: Request) -> RedirectResponse:
        form = await request.form()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        if (
            username == settings.session.admin_username
            and settings.session.admin_password
            and password == settings.session.admin_password
        ):
            request.session["authenticated"] = True
            request.session["username"] = username
            return RedirectResponse(url="/", status_code=303)
        return RedirectResponse(url="/login?error=1", status_code=303)

    @router.post("/logout")
    async def logout(request: Request) -> RedirectResponse:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    @router.get("/ui/auth-state")
    async def auth_state(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "auth_enabled": settings.auth.enabled,
                "session_authenticated": is_ui_session_authenticated(request, settings),
                "username": request.session.get("username"),
            }
        )

    @router.get("/ui/app.js")
    async def app_js() -> FileResponse:
        return FileResponse(UI_DIR / "app.js", media_type="application/javascript")

    @router.get("/ui/styles.css")
    async def styles_css() -> FileResponse:
        return FileResponse(UI_DIR / "styles.css", media_type="text/css")

    return router
