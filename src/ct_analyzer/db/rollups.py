from __future__ import annotations

from ct_analyzer.db.clickhouse import ClickHouseRepository


def refresh_rollups(repository: ClickHouseRepository, days: int) -> None:
    repository.refresh_rollups(days)
