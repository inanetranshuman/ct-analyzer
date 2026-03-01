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


def _issuer_profile_payload(repository: ClickHouseRepository, days: int) -> dict[str, Any]:
    return repository.query_issuer_profile(days)


def _issuer_breakdown_payload(
    repository: ClickHouseRepository,
    group_by: str,
    days: int,
    limit: int,
) -> dict[str, Any]:
    return repository.query_issuer_breakdown(group_by, days, limit)


def _certificate_details_payload(repository: ClickHouseRepository, cert_hash: str) -> dict[str, Any] | None:
    return repository.get_certificate_details(cert_hash)


def _certificate_search_payload(
    repository: ClickHouseRepository,
    *,
    days: int,
    limit: int,
    registered_domain: str | None = None,
    subject_cn_contains: str | None = None,
    issuer_contains: str | None = None,
    eku_contains: str | None = None,
    has_wildcard: bool | None = None,
    has_punycode: bool | None = None,
    min_anomaly_score: int | None = None,
) -> dict[str, Any]:
    return {
        "days": days,
        "limit": limit,
        "results": repository.search_recent_certificates(
            days=days,
            limit=limit,
            registered_domain=registered_domain,
            subject_cn_contains=subject_cn_contains,
            issuer_contains=issuer_contains,
            eku_contains=eku_contains,
            has_wildcard=has_wildcard,
            has_punycode=has_punycode,
            min_anomaly_score=min_anomaly_score,
        ),
    }


def _domain_activity_payload(
    repository: ClickHouseRepository,
    registered_domain: str,
    days: int,
    limit: int,
) -> dict[str, Any]:
    return repository.get_domain_activity(registered_domain, days, limit)


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

    @mcp.tool()
    async def get_issuer_profile(days: int = 30) -> dict[str, Any]:
        """Return a baseline profile for normal GoDaddy/Starfield certificate attributes."""
        repository = get_repository()
        return await asyncio.to_thread(_issuer_profile_payload, repository, days)

    @mcp.tool()
    async def get_issuer_breakdown(group_by: str = "sig_alg", days: int = 30, limit: int = 10) -> dict[str, Any]:
        """Return grouped GoDaddy/Starfield counts by a bounded set of useful dimensions."""
        repository = get_repository()
        return await asyncio.to_thread(_issuer_breakdown_payload, repository, group_by, days, limit)

    @mcp.tool()
    async def get_certificate(cert_hash: str) -> dict[str, Any]:
        """Return a single certificate record plus findings by certificate hash."""
        repository = get_repository()
        payload = await asyncio.to_thread(_certificate_details_payload, repository, cert_hash)
        if payload is None:
            return {"cert_hash": cert_hash, "found": False}
        payload["found"] = True
        return payload

    @mcp.tool()
    async def search_recent_certificates(
        days: int = 7,
        limit: int = 25,
        registered_domain: str | None = None,
        subject_cn_contains: str | None = None,
        issuer_contains: str | None = None,
        eku_contains: str | None = None,
        has_wildcard: bool | None = None,
        has_punycode: bool | None = None,
        min_anomaly_score: int | None = None,
    ) -> dict[str, Any]:
        """Search recent certificates with bounded filters for investigation pivots."""
        repository = get_repository()
        return await asyncio.to_thread(
            _certificate_search_payload,
            repository,
            days=days,
            limit=limit,
            registered_domain=registered_domain,
            subject_cn_contains=subject_cn_contains,
            issuer_contains=issuer_contains,
            eku_contains=eku_contains,
            has_wildcard=has_wildcard,
            has_punycode=has_punycode,
            min_anomaly_score=min_anomaly_score,
        )

    @mcp.tool()
    async def get_domain_activity(registered_domain: str, days: int = 7, limit: int = 25) -> dict[str, Any]:
        """Return recent activity for one registered domain."""
        repository = get_repository()
        return await asyncio.to_thread(_domain_activity_payload, repository, registered_domain, days, limit)

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

    @mcp.resource("ct://issuer/godaddy/profile/{days}")
    async def issuer_profile_resource(days: int) -> str:
        """Read-only JSON snapshot of the GoDaddy/Starfield issuer baseline profile."""
        repository = get_repository()
        payload = await asyncio.to_thread(_issuer_profile_payload, repository, days)
        return json.dumps(payload, indent=2, sort_keys=True)

    @mcp.resource("ct://issuer/godaddy/breakdown/{group_by}/{days}/{limit}")
    async def issuer_breakdown_resource(group_by: str, days: int, limit: int) -> str:
        """Read-only JSON snapshot of a bounded grouped issuer breakdown."""
        repository = get_repository()
        payload = await asyncio.to_thread(_issuer_breakdown_payload, repository, group_by, days, limit)
        return json.dumps(payload, indent=2, sort_keys=True)

    @mcp.resource("ct://certificate/{cert_hash}")
    async def certificate_resource(cert_hash: str) -> str:
        """Read-only JSON snapshot of one certificate and its findings."""
        repository = get_repository()
        payload = await asyncio.to_thread(_certificate_details_payload, repository, cert_hash)
        return json.dumps(payload or {"cert_hash": cert_hash, "found": False}, indent=2, sort_keys=True)

    @mcp.resource("ct://domain/{registered_domain}/activity/{days}/{limit}")
    async def domain_activity_resource(registered_domain: str, days: int, limit: int) -> str:
        """Read-only JSON snapshot of recent activity for one registered domain."""
        repository = get_repository()
        payload = await asyncio.to_thread(_domain_activity_payload, repository, registered_domain, days, limit)
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
