from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from ct_analyzer.config import Settings
from ct_analyzer.db.clickhouse import ClickHouseRepository
from ct_analyzer.security import require_api_key


class HealthResponse(BaseModel):
    status: str


class IssuerStatsResponse(BaseModel):
    issuer: str
    days: int
    aggregated_counts: dict[str, int]


class AnomalyRecordResponse(BaseModel):
    cert_hash: str
    subject_cn: str
    dns_names: list[str]
    anomaly_score: int
    top_signals: list[dict[str, Any]]
    evidence: dict[str, Any]
    finding_severity_counts: dict[str, int]


class IssuerAnomaliesResponse(BaseModel):
    issuer: str
    days: int
    limit: int
    aggregated_counts: dict[str, int]
    top_anomalies: list[AnomalyRecordResponse]


def build_router(
    get_repository: Callable[[], ClickHouseRepository],
    settings: Settings,
) -> APIRouter:
    router = APIRouter()

    async def auth_dependency(request: Request) -> None:
        await require_api_key(request, settings)

    @router.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @router.get("/stats/issuer/godaddy", response_model=IssuerStatsResponse)
    async def issuer_stats(
        days: int = Query(default=30, ge=1, le=365),
        _auth: None = Depends(auth_dependency),
        repository: ClickHouseRepository = Depends(get_repository),
    ) -> IssuerStatsResponse:
        stats = await asyncio.to_thread(repository.query_issuer_stats, days)
        return IssuerStatsResponse(
            issuer="godaddy",
            days=days,
            aggregated_counts={key: value for key, value in stats.items() if key != "days"},
        )

    @router.get("/anomalies/issuer/godaddy", response_model=IssuerAnomaliesResponse)
    async def issuer_anomalies(
        days: int = Query(default=7, ge=1, le=365),
        limit: int = Query(default=50, ge=1, le=200),
        _auth: None = Depends(auth_dependency),
        repository: ClickHouseRepository = Depends(get_repository),
    ) -> IssuerAnomaliesResponse:
        stats = await asyncio.to_thread(repository.query_issuer_stats, days)
        anomalies = await asyncio.to_thread(repository.query_anomalies, days, limit)
        return IssuerAnomaliesResponse(
            issuer="godaddy",
            days=days,
            limit=limit,
            aggregated_counts={key: value for key, value in stats.items() if key != "days"},
            top_anomalies=[AnomalyRecordResponse(**row) for row in anomalies],
        )

    return router
