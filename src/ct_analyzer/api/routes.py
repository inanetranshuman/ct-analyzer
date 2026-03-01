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


class IssuerProfileResponse(BaseModel):
    issuer: str
    days: int
    cert_count: int
    validity_days: dict[str, float]
    san_count: dict[str, float]
    feature_rates: dict[str, float]
    top_signature_algorithms: list[dict[str, Any]]
    top_key_types: list[dict[str, Any]]
    top_key_sizes: list[dict[str, Any]]
    top_eku_sets: list[dict[str, Any]]


class IssuerBreakdownResponse(BaseModel):
    issuer: str
    days: int
    group_by: str
    label: str
    buckets: list[dict[str, Any]]


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


class CertificateDetailResponse(BaseModel):
    cert_hash: str
    subject_cn: str
    subject_dn: str
    issuer_cn: str
    issuer_dn: str
    serial_number: str
    dns_names: list[str]
    anomaly_score: int
    findings: list[dict[str, Any]]


class CertificateSearchResponse(BaseModel):
    days: int
    limit: int
    results: list[dict[str, Any]]


class DomainActivityResponse(BaseModel):
    registered_domain: str
    days: int
    activity: list[dict[str, Any]]


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

    @router.get("/profile/issuer/godaddy", response_model=IssuerProfileResponse)
    async def issuer_profile(
        days: int = Query(default=30, ge=1, le=365),
        _auth: None = Depends(auth_dependency),
        repository: ClickHouseRepository = Depends(get_repository),
    ) -> IssuerProfileResponse:
        profile = await asyncio.to_thread(repository.query_issuer_profile, days)
        return IssuerProfileResponse(**profile)

    @router.get("/breakdown/issuer/godaddy", response_model=IssuerBreakdownResponse)
    async def issuer_breakdown(
        group_by: str = Query(
            default="sig_alg",
            pattern="^(issuer_cn|issuer_dn|sig_alg|key_type|key_size|eku_set|finding_code|severity|anomaly_bucket|registered_domain|validity_bucket|san_count_bucket)$",
        ),
        days: int = Query(default=30, ge=1, le=365),
        limit: int = Query(default=10, ge=1, le=100),
        _auth: None = Depends(auth_dependency),
        repository: ClickHouseRepository = Depends(get_repository),
    ) -> IssuerBreakdownResponse:
        payload = await asyncio.to_thread(repository.query_issuer_breakdown, group_by, days, limit)
        return IssuerBreakdownResponse(**payload)

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

    @router.get("/certificates/search", response_model=CertificateSearchResponse)
    async def search_certificates(
        days: int = Query(default=7, ge=1, le=30),
        limit: int = Query(default=25, ge=1, le=100),
        registered_domain: str | None = Query(default=None),
        subject_cn_contains: str | None = Query(default=None),
        issuer_contains: str | None = Query(default=None),
        has_wildcard: bool | None = Query(default=None),
        has_punycode: bool | None = Query(default=None),
        min_anomaly_score: int | None = Query(default=None, ge=0, le=100),
        _auth: None = Depends(auth_dependency),
        repository: ClickHouseRepository = Depends(get_repository),
    ) -> CertificateSearchResponse:
        results = await asyncio.to_thread(
            repository.search_recent_certificates,
            days=days,
            limit=limit,
            registered_domain=registered_domain,
            subject_cn_contains=subject_cn_contains,
            issuer_contains=issuer_contains,
            has_wildcard=has_wildcard,
            has_punycode=has_punycode,
            min_anomaly_score=min_anomaly_score,
        )
        return CertificateSearchResponse(days=days, limit=limit, results=results)

    @router.get("/certificates/{cert_hash}", response_model=CertificateDetailResponse)
    async def certificate_details(
        cert_hash: str,
        _auth: None = Depends(auth_dependency),
        repository: ClickHouseRepository = Depends(get_repository),
    ) -> CertificateDetailResponse:
        details = await asyncio.to_thread(repository.get_certificate_details, cert_hash)
        if details is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Certificate not found")
        return CertificateDetailResponse(**details)

    @router.get("/domains/{registered_domain}/activity", response_model=DomainActivityResponse)
    async def domain_activity(
        registered_domain: str,
        days: int = Query(default=7, ge=1, le=30),
        limit: int = Query(default=25, ge=1, le=100),
        _auth: None = Depends(auth_dependency),
        repository: ClickHouseRepository = Depends(get_repository),
    ) -> DomainActivityResponse:
        payload = await asyncio.to_thread(repository.get_domain_activity, registered_domain, days, limit)
        return DomainActivityResponse(**payload)

    return router
