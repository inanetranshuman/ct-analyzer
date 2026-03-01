from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings

from ct_analyzer.config import Settings
from ct_analyzer.db.clickhouse import ClickHouseRepository
from ct_analyzer.db.rollups import refresh_rollups


LOGGER = logging.getLogger(__name__)


def _issuer_stats_payload(repository: ClickHouseRepository, days: int) -> dict[str, Any]:
    stats = repository.query_issuer_stats(days)
    return {
        "issuer": "godaddy",
        "days": days,
        "aggregated_counts": {key: value for key, value in stats.items() if key != "days"},
    }


def _issuer_anomalies_payload(
    repository: ClickHouseRepository,
    days: int,
    limit: int,
) -> dict[str, Any]:
    stats = repository.query_issuer_stats(days)
    anomalies = repository.query_anomalies(days, limit)
    return {
        "issuer": "godaddy",
        "days": days,
        "limit": limit,
        "aggregated_counts": {key: value for key, value in stats.items() if key != "days"},
        "top_anomalies": anomalies,
    }


def _load_fastmcp() -> tuple[Any | None, type[Exception] | None]:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        return None, exc
    return FastMCP, None


def create_mcp_server(
    get_repository: Callable[[], ClickHouseRepository],
    settings: Settings,
) -> Any:
    fast_mcp_cls, import_error = _load_fastmcp()
    if fast_mcp_cls is None:
        raise RuntimeError(
            "MCP support requires the 'mcp' package. Reinstall the project to pick up new dependencies."
        ) from import_error

    mcp = fast_mcp_cls(
        "ct-analyzer",
        instructions=(
            "Use the issuer stats and anomaly tools to answer questions about GoDaddy and "
            "Starfield-issued CT certificates. Prefer bounded time windows and limits."
        ),
        json_response=True,
        stateless_http=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=settings.mcp.allowed_hosts,
            allowed_origins=settings.mcp.allowed_origins,
        ),
    )

    @mcp.tool()
    async def get_issuer_stats(days: int = 30) -> dict[str, Any]:
        """Return aggregated GoDaddy/Starfield issuer counts for a bounded time window."""
        repository = get_repository()
        return await asyncio.to_thread(_issuer_stats_payload, repository, days)

    @mcp.tool()
    async def get_anomalies(days: int = 7, limit: int = 50) -> dict[str, Any]:
        """Return top anomaly records for GoDaddy/Starfield certificates."""
        repository = get_repository()
        return await asyncio.to_thread(_issuer_anomalies_payload, repository, days, limit)

    if settings.mcp.enable_admin_tools:

        @mcp.tool()
        async def run_rollup(days: int = 30) -> dict[str, Any]:
            """Refresh issuer rollups for the requested trailing day window."""
            repository = get_repository()
            await asyncio.to_thread(refresh_rollups, repository, days)
            return {"status": "ok", "days": days}

    @mcp.resource("ct://issuer/godaddy/stats/{days}")
    async def issuer_stats_resource(days: int) -> str:
        """Read-only JSON snapshot of issuer stats."""
        repository = get_repository()
        payload = await asyncio.to_thread(_issuer_stats_payload, repository, days)
        return json.dumps(payload, indent=2, sort_keys=True)

    @mcp.resource("ct://issuer/godaddy/anomalies/{days}/{limit}")
    async def issuer_anomalies_resource(days: int, limit: int) -> str:
        """Read-only JSON snapshot of current anomaly results."""
        repository = get_repository()
        payload = await asyncio.to_thread(_issuer_anomalies_payload, repository, days, limit)
        return json.dumps(payload, indent=2, sort_keys=True)

    @mcp.prompt()
    def analyze_godaddy_ct(days: int = 7, limit: int = 20) -> str:
        """Guide an MCP client to inspect issuer stats and anomalies before answering."""
        return (
            "Use get_issuer_stats(days={days}) to understand issuance volume and feature counts, "
            "then use get_anomalies(days={days}, limit={limit}) to inspect the highest scoring "
            "certificates. Summarize the notable patterns, mention top signals, and cite cert hashes."
        ).format(days=days, limit=limit)

    return mcp


def mcp_dependency_error() -> str | None:
    _, import_error = _load_fastmcp()
    if import_error is None:
        return None
    return "MCP support requires reinstalling with the new 'mcp' dependency."
