from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from functools import lru_cache
import logging

import uvicorn
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from ct_analyzer.api.routes import build_router
from ct_analyzer.api.ui import build_ui_router
from ct_analyzer.config import Settings, get_settings
from ct_analyzer.db.clickhouse import ClickHouseRepository
from ct_analyzer.mcp_server import create_mcp_server, mcp_dependency_error
from ct_analyzer.security import APIKeyASGIMiddleware, SessionCookieSecurityMiddleware


LOGGER = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _repository() -> ClickHouseRepository:
    return ClickHouseRepository(get_settings())


@lru_cache(maxsize=1)
def _mcp_server() -> object | None:
    error = mcp_dependency_error()
    if error:
        LOGGER.warning("%s REST API will continue without MCP mounting.", error)
        return None
    return create_mcp_server(_repository, get_settings())


def create_app(settings: Settings | None = None) -> FastAPI:
    effective_settings = settings or get_settings()
    mcp_server = _mcp_server()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with AsyncExitStack() as stack:
            if mcp_server is not None:
                await stack.enter_async_context(mcp_server.session_manager.run())
            yield

    app = FastAPI(title="ct-analyzer", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware,
        secret_key=effective_settings.session.secret_key,
        session_cookie=effective_settings.session.cookie_name,
        same_site="lax",
        https_only=effective_settings.session.https_only,
    )
    app.add_middleware(SessionCookieSecurityMiddleware, settings=effective_settings)
    app.include_router(build_ui_router(effective_settings))
    app.include_router(build_router(lambda: _repository(), effective_settings))
    if mcp_server is not None:
        app.mount("/mcp", APIKeyASGIMiddleware(mcp_server.streamable_http_app(), effective_settings))
    return app


def run_api(settings: Settings | None = None) -> None:
    effective_settings = settings or get_settings()
    uvicorn.run(
        "ct_analyzer.api.server:create_app",
        factory=True,
        host=effective_settings.api.host,
        port=effective_settings.api.port,
    )
