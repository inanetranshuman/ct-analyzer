from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass(slots=True)
class IssuerBaseline:
    issuer_key: str
    validity_p50: float = 0.0
    validity_p95: float = 0.0
    wildcard_rate: float = 0.0
    punycode_rate: float = 0.0
    ip_san_rate: float = 0.0
    uri_san_rate: float = 0.0
    email_san_rate: float = 0.0
    common_eku_sets: set[str] = field(default_factory=set)
    current_day_count: int = 0
    trailing_daily_avg: float = 0.0


class BaselineCache:
    def __init__(self, repository: object, ttl_seconds: int = 300) -> None:
        self._repository = repository
        self._ttl_seconds = ttl_seconds
        self._cache: dict[str, tuple[datetime, IssuerBaseline]] = {}
        self._lock = asyncio.Lock()

    async def get(self, issuer_key: str, days: int) -> IssuerBaseline:
        now = datetime.now(tz=UTC)
        async with self._lock:
            cached = self._cache.get(issuer_key)
            if cached and (now - cached[0]) < timedelta(seconds=self._ttl_seconds):
                return cached[1]
            baseline = await asyncio.to_thread(self._repository.fetch_issuer_baseline, issuer_key, days)
            self._cache[issuer_key] = (now, baseline)
            return baseline
