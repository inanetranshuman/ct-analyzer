import json
from types import SimpleNamespace

from ct_analyzer.db.clickhouse import ClickHouseRepository


class _QueryResult:
    def __init__(self, first_row):
        self.first_row = first_row


def test_query_dashboard_snapshot_prefers_cached_breakdown() -> None:
    payload = {
        "issuer": "godaddy",
        "days": 30,
        "updated_at": "2025-03-05T00:00:00+00:00",
        "aggregated_counts": {"cert_count": 1},
        "profile": {},
        "findings": {},
        "anomalies": {},
        "breakdowns": {
            "issuer_cn": {
                "issuer": "godaddy",
                "days": 30,
                "group_by": "issuer_cn",
                "label": "Issuer CN",
                "buckets": [{"value": "Go Daddy", "count": 1}],
            }
        },
    }
    repository = ClickHouseRepository.__new__(ClickHouseRepository)
    repository._local = SimpleNamespace(
        client=SimpleNamespace(query=lambda *_args, **_kwargs: _QueryResult((json.dumps(payload),)))
    )
    repository._qualified = lambda table: table
    repository.query_issuer_breakdown = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("live breakdown query should not run")
    )

    result = repository.query_dashboard_snapshot(30, "issuer_cn")

    assert result["selected_breakdown"] == payload["breakdowns"]["issuer_cn"]


def test_query_dashboard_snapshot_falls_back_for_legacy_snapshot() -> None:
    payload = {
        "issuer": "godaddy",
        "days": 30,
        "updated_at": "2025-03-05T00:00:00+00:00",
        "aggregated_counts": {"cert_count": 1},
        "profile": {},
        "findings": {},
        "anomalies": {},
    }
    repository = ClickHouseRepository.__new__(ClickHouseRepository)
    repository._local = SimpleNamespace(
        client=SimpleNamespace(query=lambda *_args, **_kwargs: _QueryResult((json.dumps(payload),)))
    )
    repository._qualified = lambda table: table
    repository.query_issuer_breakdown = lambda group_by, days, limit: {
        "issuer": "godaddy",
        "days": days,
        "group_by": group_by,
        "label": "Issuer CN",
        "buckets": [{"value": "Go Daddy", "count": limit}],
    }

    result = repository.query_dashboard_snapshot(30, "issuer_cn")

    assert result["selected_breakdown"]["group_by"] == "issuer_cn"
    assert result["selected_breakdown"]["buckets"] == [{"value": "Go Daddy", "count": 12}]
