from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

import clickhouse_connect

from ct_analyzer.analysis.baseline import IssuerBaseline
from ct_analyzer.cert.domains import to_unicode_hostname
from ct_analyzer.cert.x509_features import validation_type_from_policy_oids
from ct_analyzer.config import Settings
from ct_analyzer.db.migrations import load_schema_sql


LOGGER = logging.getLogger(__name__)


class ClickHouseRepository:
    DASHBOARD_WINDOWS = (7, 30, 90, 365)
    DASHBOARD_GROUP_BYS = (
        "issuer_cn",
        "validation_type",
        "sig_alg",
        "key_type",
        "key_size",
        "eku_set",
        "finding_code",
        "severity",
        "anomaly_bucket",
        "registered_domain",
        "validity_bucket",
        "san_count_bucket",
    )

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.database = settings.clickhouse.database
        self._local = threading.local()
        self._base_client = clickhouse_connect.get_client(
            host=settings.clickhouse.host,
            port=settings.clickhouse.port,
            username=settings.clickhouse.user,
            password=settings.clickhouse.password,
            database="default",
        )

    def _qualified(self, table: str) -> str:
        return f"{self.database}.{table}"

    @staticmethod
    def _validation_type_expr(alias: str | None = "c") -> str:
        prefix = f"{alias}." if alias else ""
        return (
            f"multiIf("
            f"has({prefix}policy_oids, '2.23.140.1.1'), 'EV', "
            f"has({prefix}policy_oids, '2.23.140.1.2.2'), 'OV', "
            f"has({prefix}policy_oids, '2.23.140.1.2.1'), 'DV', "
            f"'Unknown'"
            f")"
        )

    @staticmethod
    def _quoted_string_list(values: list[str]) -> str:
        escaped_values = [value.replace("'", "''") for value in values]
        return ", ".join(f"'{value}'" for value in escaped_values)

    def _new_client(self):
        return clickhouse_connect.get_client(
            host=self.settings.clickhouse.host,
            port=self.settings.clickhouse.port,
            username=self.settings.clickhouse.user,
            password=self.settings.clickhouse.password,
            database="default",
        )

    @staticmethod
    def _range_bounds(date_from: date, date_to: date) -> tuple[datetime, datetime]:
        if date_to < date_from:
            raise ValueError("date_to must be on or after date_from")
        start = datetime.combine(date_from, datetime.min.time(), tzinfo=UTC)
        end = datetime.combine(date_to + timedelta(days=1), datetime.min.time(), tzinfo=UTC)
        return start, end

    @property
    def client(self):
        client = getattr(self._local, "client", None)
        if client is None:
            client = self._new_client()
            self._local.client = client
        return client

    def migrate(self) -> None:
        statements = load_schema_sql()
        for statement in statements:
            rewritten = statement.replace(
                "CREATE DATABASE IF NOT EXISTS ct_analyzer",
                f"CREATE DATABASE IF NOT EXISTS {self.database}",
            ).replace("ct_analyzer.", f"{self.database}.")
            LOGGER.info("Applying migration statement")
            self._base_client.command(rewritten)

    def insert_rows(self, table: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        columns = list(rows[0].keys())
        payload = [[row.get(column) for column in columns] for row in rows]
        self._insert_payload(table, payload, columns)

    def _insert_payload(self, table: str, payload: list[list[Any]], columns: list[str]) -> None:
        try:
            self.client.insert(self._qualified(table), payload, column_names=columns)
        except Exception as exc:
            message = str(exc)
            if "MEMORY_LIMIT_EXCEEDED" in message and len(payload) > 1:
                midpoint = len(payload) // 2
                LOGGER.warning(
                    "ClickHouse insert for %s exceeded memory with %s rows; retrying as %s + %s rows",
                    table,
                    len(payload),
                    midpoint,
                    len(payload) - midpoint,
                )
                self._insert_payload(table, payload[:midpoint], columns)
                self._insert_payload(table, payload[midpoint:], columns)
                return
            raise

    def insert_certificates(self, rows: list[dict[str, Any]]) -> None:
        deduped: dict[str, dict[str, Any]] = {}
        for row in rows:
            existing = deduped.get(row["cert_hash"])
            if existing is None or row["last_seen"] >= existing["last_seen"]:
                deduped[row["cert_hash"]] = row
        self.insert_rows("certificates", list(deduped.values()))

    def insert_observations(self, rows: list[dict[str, Any]]) -> None:
        self.insert_rows("observations", rows)

    def insert_findings(self, rows: list[dict[str, Any]]) -> None:
        self.insert_rows("cert_findings", rows)

    def refresh_rollups(self, days: int) -> None:
        updated_at = datetime.now(tz=UTC)
        effective_days = max(days, 1)
        daily_query = f"""
            INSERT INTO {self._qualified("issuer_daily_stats")}
            SELECT
                toDate(o.seen_at) AS day,
                o.issuer_key AS issuer_key,
                uniqExact(o.cert_hash) AS cert_count,
                uniqExact(o.registered_domain) AS domain_count,
                sum(c.has_wildcard) AS wildcard_count,
                sum(c.has_punycode) AS punycode_count,
                sum(c.has_ip_san) AS ip_san_count,
                sum(c.has_uri_san) AS uri_san_count,
                sum(c.has_email_san) AS email_san_count,
                sum(if(length(c.eku) > 0 AND has(c.eku, 'serverAuth') = 0, 1, 0)) AS unusual_eku_count,
                sum(c.basic_constraints_ca) AS ca_true_leaf_count,
                %(updated_at)s AS updated_at
            FROM {self._qualified("observations")} AS o
            INNER JOIN (SELECT * FROM {self._qualified("certificates")} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            WHERE o.seen_at >= %(cutoff)s
            GROUP BY day, issuer_key
        """
        sigalg_query = f"""
            INSERT INTO {self._qualified("issuer_sigalg_stats")}
            SELECT
                toDate(o.seen_at) AS day,
                o.issuer_key AS issuer_key,
                c.sig_alg AS sig_alg,
                count() AS count,
                %(updated_at)s AS updated_at
            FROM {self._qualified("observations")} AS o
            INNER JOIN (SELECT * FROM {self._qualified("certificates")} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            WHERE o.seen_at >= %(cutoff)s
            GROUP BY day, issuer_key, sig_alg
        """
        parameters = {"cutoff": datetime.now(tz=UTC) - timedelta(days=effective_days), "updated_at": updated_at}
        self.client.command(daily_query, parameters=parameters)
        try:
            self.client.command(sigalg_query, parameters=parameters)
        except Exception as exc:
            if "MEMORY_LIMIT_EXCEEDED" not in str(exc):
                raise
            LOGGER.warning("Skipping sigalg rollup for %s-day window due to memory pressure.", days)

        target_windows = [window for window in self.DASHBOARD_WINDOWS if window <= days]
        target_windows.append(days)
        self.refresh_dashboard_snapshots(sorted(set(target_windows)))

    def _build_dashboard_snapshot(self, days: int) -> dict[str, Any]:
        stats = self.query_issuer_stats(days)
        profile = self.query_issuer_profile(days)
        findings = self.query_issuer_breakdown("finding_code", days, 5)
        anomalies = self.query_anomalies(min(days, 14), 12)
        return {
            "issuer": "godaddy",
            "days": days,
            "updated_at": datetime.now(tz=UTC).isoformat(),
            "aggregated_counts": {key: value for key, value in stats.items() if key != "days"},
            "profile": profile,
            "findings": findings,
            "anomalies": {
                "issuer": "godaddy",
                "days": min(days, 14),
                "limit": 12,
                "top_anomalies": anomalies,
            },
        }

    def refresh_dashboard_snapshots(self, windows: list[int] | None = None) -> None:
        target_windows = windows or list(self.DASHBOARD_WINDOWS)
        updated_at = datetime.now(tz=UTC)
        for window_days in sorted({int(window) for window in target_windows if int(window) > 0}):
            try:
                payload = self._build_dashboard_snapshot(window_days)
                self.insert_rows(
                    "dashboard_snapshots",
                    [
                        {
                            "days": window_days,
                            "payload_json": json.dumps(payload),
                            "updated_at": updated_at,
                        }
                    ],
                )
            except Exception:
                LOGGER.exception("Failed to refresh dashboard snapshot for %s-day window", window_days)

    def query_dashboard_snapshot(self, days: int, group_by: str) -> dict[str, Any]:
        if group_by not in self.DASHBOARD_GROUP_BYS:
            raise ValueError(f"Unsupported group_by value: {group_by}")
        row = self.client.query(
            f"""
            SELECT payload_json
            FROM {self._qualified("dashboard_snapshots")} FINAL
            WHERE days = %(days)s
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            parameters={"days": days},
        ).first_row
        if not row:
            raise ValueError(f"No dashboard snapshot available for {days}-day window. Run rollup first.")
        payload = json.loads(row[0])
        try:
            requested_breakdown = self.query_issuer_breakdown(group_by, days, 12)
        except Exception as exc:
            if "MEMORY_LIMIT_EXCEEDED" not in str(exc):
                raise
            LOGGER.warning(
                "Dashboard breakdown query exceeded memory for group_by=%s days=%s; returning empty buckets.",
                group_by,
                days,
            )
            requested_breakdown = {
                "issuer": "godaddy",
                "days": days,
                "group_by": group_by,
                "label": group_by,
                "buckets": [],
            }
        payload["selected_breakdown"] = requested_breakdown
        return payload

    def fetch_issuer_baseline(self, issuer_key: str, days: int) -> IssuerBaseline:
        cutoff = datetime.now(tz=UTC) - timedelta(days=days)
        baseline = IssuerBaseline(issuer_key=issuer_key)
        certificate_table = self._qualified("certificates")
        observation_table = self._qualified("observations")
        issuer_daily_stats_table = self._qualified("issuer_daily_stats")

        row = self.client.query(
            f"""
            SELECT
                quantileTDigest(0.5)(c.validity_days) AS validity_p50,
                quantileTDigest(0.95)(c.validity_days) AS validity_p95,
                avg(c.has_wildcard) AS wildcard_rate,
                avg(c.has_punycode) AS punycode_rate,
                avg(c.has_ip_san) AS ip_san_rate,
                avg(c.has_uri_san) AS uri_san_rate,
                avg(c.has_email_san) AS email_san_rate
            FROM {observation_table} AS o
            INNER JOIN (SELECT * FROM {certificate_table} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            WHERE o.issuer_key = %(issuer_key)s
              AND o.seen_at >= %(cutoff)s
            """,
            parameters={"issuer_key": issuer_key, "cutoff": cutoff},
        ).first_row
        if row:
            baseline.validity_p50 = float(row[0] or 0.0)
            baseline.validity_p95 = float(row[1] or 0.0)
            baseline.wildcard_rate = float(row[2] or 0.0)
            baseline.punycode_rate = float(row[3] or 0.0)
            baseline.ip_san_rate = float(row[4] or 0.0)
            baseline.uri_san_rate = float(row[5] or 0.0)
            baseline.email_san_rate = float(row[6] or 0.0)

        eku_rows = self.client.query(
            f"""
            SELECT arrayStringConcat(arraySort(c.eku), ',') AS eku_key, count() AS count
            FROM {observation_table} AS o
            INNER JOIN (SELECT * FROM {certificate_table} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            WHERE o.issuer_key = %(issuer_key)s
              AND o.seen_at >= %(cutoff)s
            GROUP BY eku_key
            ORDER BY count DESC
            LIMIT 5
            """,
            parameters={"issuer_key": issuer_key, "cutoff": cutoff},
        ).result_rows
        baseline.common_eku_sets = {row[0] for row in eku_rows if row[0]}

        spike_rows = self.client.query(
            f"""
            SELECT day, cert_count
            FROM {issuer_daily_stats_table} FINAL
            WHERE issuer_key = %(issuer_key)s
              AND day >= %(day_cutoff)s
            ORDER BY day DESC
            LIMIT 8
            """,
            parameters={"issuer_key": issuer_key, "day_cutoff": date.today() - timedelta(days=8)},
        ).result_rows
        if spike_rows:
            baseline.current_day_count = int(spike_rows[0][1])
            trailing = [int(row[1]) for row in spike_rows[1:]]
            baseline.trailing_daily_avg = sum(trailing) / len(trailing) if trailing else 0.0
        return baseline

    def fetch_registered_domain_burst_counts(
        self,
        registered_domains: list[str],
        window_hours: int,
    ) -> dict[str, int]:
        domains = sorted({domain for domain in registered_domains if domain})
        if not domains:
            return {}
        cutoff = datetime.now(tz=UTC) - timedelta(hours=window_hours)
        rows = self.client.query(
            f"""
            SELECT
                registered_domain,
                uniqExact(cert_hash) AS cert_count
            FROM {self._qualified("observations")}
            WHERE seen_at >= %(cutoff)s
              AND registered_domain IN ({self._quoted_string_list(domains)})
            GROUP BY registered_domain
            """,
            parameters={"cutoff": cutoff},
        ).result_rows
        return {domain: int(count) for domain, count in rows}

    def query_issuer_stats(self, days: int) -> dict[str, Any]:
        cutoff = date.today() - timedelta(days=days)
        rows = self.client.query(
            f"""
            SELECT
                sum(cert_count) AS cert_count,
                sum(domain_count) AS domain_count,
                sum(wildcard_count) AS wildcard_count,
                sum(punycode_count) AS punycode_count,
                sum(ip_san_count) AS ip_san_count,
                sum(uri_san_count) AS uri_san_count,
                sum(email_san_count) AS email_san_count,
                sum(unusual_eku_count) AS unusual_eku_count,
                sum(ca_true_leaf_count) AS ca_true_leaf_count
            FROM {self._qualified("issuer_daily_stats")} FINAL
            WHERE day >= %(cutoff)s
            """,
            parameters={"cutoff": cutoff},
        ).first_row or (0, 0, 0, 0, 0, 0, 0, 0, 0)
        validation_row = self.client.query(
            f"""
            SELECT
                countIf(validation_type = 'DV') AS dv_count,
                countIf(validation_type = 'OV') AS ov_count,
                countIf(validation_type = 'EV') AS ev_count,
                countIf(validation_type = 'Unknown') AS unknown_validation_count
            FROM
            (
                SELECT {self._validation_type_expr(None)} AS validation_type
                FROM {self._qualified("certificates")} FINAL
                WHERE last_seen >= %(cert_cutoff)s
            )
            """,
            parameters={"cert_cutoff": datetime.now(tz=UTC) - timedelta(days=days)},
        ).first_row or (0, 0, 0, 0)
        return {
            "days": days,
            "cert_count": int(rows[0]),
            "domain_count": int(rows[1]),
            "wildcard_count": int(rows[2]),
            "punycode_count": int(rows[3]),
            "ip_san_count": int(rows[4]),
            "uri_san_count": int(rows[5]),
            "email_san_count": int(rows[6]),
            "unusual_eku_count": int(rows[7]),
            "ca_true_leaf_count": int(rows[8]),
            "dv_count": int(validation_row[0]),
            "ov_count": int(validation_row[1]),
            "ev_count": int(validation_row[2]),
            "unknown_validation_count": int(validation_row[3]),
        }

    def query_issuer_stats_range(self, date_from: date, date_to: date) -> dict[str, Any]:
        start, end = self._range_bounds(date_from, date_to)
        rows = self.client.query(
            f"""
            SELECT
                uniqExact(o.cert_hash) AS cert_count,
                uniqExact(o.registered_domain) AS domain_count,
                uniqExactIf(o.cert_hash, c.has_wildcard = 1) AS wildcard_count,
                uniqExactIf(o.cert_hash, c.has_punycode = 1) AS punycode_count,
                uniqExactIf(o.cert_hash, c.has_ip_san = 1) AS ip_san_count,
                uniqExactIf(o.cert_hash, c.has_uri_san = 1) AS uri_san_count,
                uniqExactIf(o.cert_hash, c.has_email_san = 1) AS email_san_count,
                uniqExactIf(o.cert_hash, length(c.eku) > 0 AND has(c.eku, 'serverAuth') = 0) AS unusual_eku_count,
                uniqExactIf(o.cert_hash, c.basic_constraints_ca = 1) AS ca_true_leaf_count
            FROM {self._qualified("observations")} AS o
            INNER JOIN (SELECT * FROM {self._qualified("certificates")} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            WHERE o.seen_at >= %(start)s
              AND o.seen_at < %(end)s
            """,
            parameters={"start": start, "end": end},
        ).first_row or (0, 0, 0, 0, 0, 0, 0, 0, 0)
        validation_row = self.client.query(
            f"""
            SELECT
                countIf(validation_type = 'DV') AS dv_count,
                countIf(validation_type = 'OV') AS ov_count,
                countIf(validation_type = 'EV') AS ev_count,
                countIf(validation_type = 'Unknown') AS unknown_validation_count
            FROM
            (
                SELECT {self._validation_type_expr(None)} AS validation_type
                FROM {self._qualified("certificates")} FINAL
                WHERE last_seen >= %(start)s
                  AND last_seen < %(end)s
            )
            """,
            parameters={"start": start, "end": end},
        ).first_row or (0, 0, 0, 0)
        return {
            "issuer": "godaddy",
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "aggregated_counts": {
                "cert_count": int(rows[0]),
                "domain_count": int(rows[1]),
                "wildcard_count": int(rows[2]),
                "punycode_count": int(rows[3]),
                "ip_san_count": int(rows[4]),
                "uri_san_count": int(rows[5]),
                "email_san_count": int(rows[6]),
                "unusual_eku_count": int(rows[7]),
                "ca_true_leaf_count": int(rows[8]),
                "dv_count": int(validation_row[0]),
                "ov_count": int(validation_row[1]),
                "ev_count": int(validation_row[2]),
                "unknown_validation_count": int(validation_row[3]),
            },
        }

    def query_issuer_daily_counts(self, date_from: date, date_to: date) -> dict[str, Any]:
        start, end = self._range_bounds(date_from, date_to)
        rows = self.client.query(
            f"""
            SELECT
                toDate(o.seen_at) AS day,
                uniqExact(o.cert_hash) AS cert_count,
                uniqExact(o.registered_domain) AS domain_count,
                uniqExactIf(o.cert_hash, c.anomaly_score >= 30) AS elevated_anomaly_count
            FROM {self._qualified("observations")} AS o
            INNER JOIN (SELECT * FROM {self._qualified("certificates")} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            WHERE o.seen_at >= %(start)s
              AND o.seen_at < %(end)s
            GROUP BY day
            ORDER BY day
            """,
            parameters={"start": start, "end": end},
        ).result_rows
        return {
            "issuer": "godaddy",
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "daily_counts": [
                {
                    "day": day.isoformat() if hasattr(day, "isoformat") else str(day),
                    "cert_count": int(cert_count),
                    "domain_count": int(domain_count),
                    "elevated_anomaly_count": int(elevated_anomaly_count),
                }
                for day, cert_count, domain_count, elevated_anomaly_count in rows
            ],
        }

    def query_issuer_profile(self, days: int) -> dict[str, Any]:
        cutoff = datetime.now(tz=UTC) - timedelta(days=days)
        summary_row = self.client.query(
            f"""
            SELECT
                uniqExact(cert_hash) AS cert_count,
                quantileTDigest(0.5)(validity_days) AS validity_p50,
                quantileTDigest(0.95)(validity_days) AS validity_p95,
                quantileTDigest(0.5)(san_count) AS san_count_p50,
                quantileTDigest(0.95)(san_count) AS san_count_p95,
                avg(has_wildcard) AS wildcard_rate,
                avg(has_punycode) AS punycode_rate,
                avg(has_ip_san) AS ip_san_rate,
                avg(has_uri_san) AS uri_san_rate,
                avg(has_email_san) AS email_san_rate,
                avg(has_must_staple) AS must_staple_rate,
                avg(basic_constraints_ca) AS ca_true_rate
            FROM {self._qualified("certificates")}
            WHERE last_seen >= %(cutoff)s
            """,
            parameters={"cutoff": cutoff},
        ).first_row or (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        def _top_rows(query: str) -> list[dict[str, Any]]:
            rows = self.client.query(query, parameters={"cutoff": cutoff}).result_rows
            return [{"value": row[0], "count": int(row[1])} for row in rows]

        top_sig_algs = _top_rows(
            f"""
            SELECT sig_alg, uniqExact(cert_hash) AS count
            FROM {self._qualified("certificates")}
            WHERE last_seen >= %(cutoff)s
            GROUP BY sig_alg
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_key_types = _top_rows(
            f"""
            SELECT key_type, uniqExact(cert_hash) AS count
            FROM {self._qualified("certificates")}
            WHERE last_seen >= %(cutoff)s
            GROUP BY key_type
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_key_sizes = _top_rows(
            f"""
            SELECT toString(key_size), uniqExact(cert_hash) AS count
            FROM {self._qualified("certificates")}
            WHERE last_seen >= %(cutoff)s
            GROUP BY key_size
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_eku_sets = _top_rows(
            f"""
            SELECT
                eku_set,
                uniqExact(cert_hash) AS count
            FROM
            (
                SELECT
                    cert_hash,
                    if(length(eku) = 0, '(none)', arrayStringConcat(arraySort(eku), ',')) AS eku_set
                FROM {self._qualified("certificates")}
                WHERE last_seen >= %(cutoff)s
            )
            GROUP BY eku_set
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_validation_types = _top_rows(
            f"""
            SELECT validation_type, uniqExact(cert_hash) AS count
            FROM
            (
                SELECT {self._validation_type_expr(None)} AS validation_type
                    , cert_hash
                FROM {self._qualified("certificates")}
                WHERE last_seen >= %(cutoff)s
            )
            GROUP BY validation_type
            ORDER BY count DESC
            LIMIT 5
            """
        )

        return {
            "issuer": "godaddy",
            "days": days,
            "cert_count": int(summary_row[0] or 0),
            "validity_days": {
                "p50": float(summary_row[1] or 0),
                "p95": float(summary_row[2] or 0),
            },
            "san_count": {
                "p50": float(summary_row[3] or 0),
                "p95": float(summary_row[4] or 0),
            },
            "feature_rates": {
                "wildcard_rate": float(summary_row[5] or 0),
                "punycode_rate": float(summary_row[6] or 0),
                "ip_san_rate": float(summary_row[7] or 0),
                "uri_san_rate": float(summary_row[8] or 0),
                "email_san_rate": float(summary_row[9] or 0),
                "must_staple_rate": float(summary_row[10] or 0),
                "ca_true_rate": float(summary_row[11] or 0),
            },
            "top_signature_algorithms": top_sig_algs,
            "top_key_types": top_key_types,
            "top_key_sizes": top_key_sizes,
            "top_eku_sets": top_eku_sets,
            "top_validation_types": top_validation_types,
        }

    def query_issuer_profile_range(self, date_from: date, date_to: date) -> dict[str, Any]:
        start, end = self._range_bounds(date_from, date_to)
        summary_row = self.client.query(
            f"""
            SELECT
                uniqExact(cert_hash) AS cert_count,
                quantileTDigest(0.5)(validity_days) AS validity_p50,
                quantileTDigest(0.95)(validity_days) AS validity_p95,
                quantileTDigest(0.5)(san_count) AS san_count_p50,
                quantileTDigest(0.95)(san_count) AS san_count_p95,
                avg(has_wildcard) AS wildcard_rate,
                avg(has_punycode) AS punycode_rate,
                avg(has_ip_san) AS ip_san_rate,
                avg(has_uri_san) AS uri_san_rate,
                avg(has_email_san) AS email_san_rate,
                avg(has_must_staple) AS must_staple_rate,
                avg(basic_constraints_ca) AS ca_true_rate
            FROM {self._qualified("certificates")}
            WHERE last_seen >= %(start)s
              AND last_seen < %(end)s
            """,
            parameters={"start": start, "end": end},
        ).first_row or (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        def _top_rows(query: str) -> list[dict[str, Any]]:
            rows = self.client.query(query, parameters={"start": start, "end": end}).result_rows
            return [{"value": row[0], "count": int(row[1])} for row in rows]

        top_sig_algs = _top_rows(
            f"""
            SELECT sig_alg, uniqExact(cert_hash) AS count
            FROM {self._qualified("certificates")}
            WHERE last_seen >= %(start)s
              AND last_seen < %(end)s
            GROUP BY sig_alg
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_key_types = _top_rows(
            f"""
            SELECT key_type, uniqExact(cert_hash) AS count
            FROM {self._qualified("certificates")}
            WHERE last_seen >= %(start)s
              AND last_seen < %(end)s
            GROUP BY key_type
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_key_sizes = _top_rows(
            f"""
            SELECT toString(key_size), uniqExact(cert_hash) AS count
            FROM {self._qualified("certificates")}
            WHERE last_seen >= %(start)s
              AND last_seen < %(end)s
            GROUP BY key_size
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_eku_sets = _top_rows(
            f"""
            SELECT
                eku_set,
                uniqExact(cert_hash) AS count
            FROM
            (
                SELECT
                    cert_hash,
                    if(length(eku) = 0, '(none)', arrayStringConcat(arraySort(eku), ',')) AS eku_set
                FROM {self._qualified("certificates")}
                WHERE last_seen >= %(start)s
                  AND last_seen < %(end)s
            )
            GROUP BY eku_set
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_validation_types = _top_rows(
            f"""
            SELECT validation_type, uniqExact(cert_hash) AS count
            FROM
            (
                SELECT {self._validation_type_expr(None)} AS validation_type
                    , cert_hash
                FROM {self._qualified("certificates")}
                WHERE last_seen >= %(start)s
                  AND last_seen < %(end)s
            )
            GROUP BY validation_type
            ORDER BY count DESC
            LIMIT 5
            """
        )

        return {
            "issuer": "godaddy",
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "cert_count": int(summary_row[0] or 0),
            "validity_days": {
                "p50": float(summary_row[1] or 0),
                "p95": float(summary_row[2] or 0),
            },
            "san_count": {
                "p50": float(summary_row[3] or 0),
                "p95": float(summary_row[4] or 0),
            },
            "feature_rates": {
                "wildcard_rate": float(summary_row[5] or 0),
                "punycode_rate": float(summary_row[6] or 0),
                "ip_san_rate": float(summary_row[7] or 0),
                "uri_san_rate": float(summary_row[8] or 0),
                "email_san_rate": float(summary_row[9] or 0),
                "must_staple_rate": float(summary_row[10] or 0),
                "ca_true_rate": float(summary_row[11] or 0),
            },
            "top_signature_algorithms": top_sig_algs,
            "top_key_types": top_key_types,
            "top_key_sizes": top_key_sizes,
            "top_eku_sets": top_eku_sets,
            "top_validation_types": top_validation_types,
        }

    def query_issuer_breakdown(self, group_by: str, days: int, limit: int) -> dict[str, Any]:
        cutoff = datetime.now(tz=UTC) - timedelta(days=days)
        groupings = {
            "issuer_cn": ("c.issuer_cn", "issuer_common_name"),
            "issuer_dn": ("c.issuer_dn", "issuer_distinguished_name"),
            "validation_type": (self._validation_type_expr(), "validation_type"),
            "sig_alg": ("c.sig_alg", "signature_algorithm"),
            "key_type": ("c.key_type", "key_type"),
            "key_size": ("toString(c.key_size)", "key_size"),
            "eku_set": ("if(length(c.eku) = 0, '(none)', arrayStringConcat(arraySort(c.eku), ','))", "eku_set"),
            "finding_code": ("f.finding_code", "finding_code"),
            "severity": ("f.severity", "severity"),
            "anomaly_bucket": (
                "multiIf(c.anomaly_score >= 60, '60+', c.anomaly_score >= 30, '30-59', c.anomaly_score >= 10, '10-29', '0-9')",
                "anomaly_bucket",
            ),
            "registered_domain": ("o.registered_domain", "registered_domain"),
            "validity_bucket": (
                "multiIf(c.validity_days <= 90, '0-90', c.validity_days <= 180, '91-180', c.validity_days <= 397, '181-397', '398+')",
                "validity_bucket",
            ),
            "san_count_bucket": (
                "multiIf(c.san_count = 1, '1', c.san_count <= 5, '2-5', c.san_count <= 25, '6-25', '26+')",
                "san_count_bucket",
            ),
        }
        if group_by not in groupings:
            raise ValueError(f"Unsupported group_by value: {group_by}")

        expr, label = groupings[group_by]
        if group_by in {"finding_code", "severity"}:
            source_column = "finding_code" if group_by == "finding_code" else "severity"
            rows = self.client.query(
                f"""
                SELECT
                    {source_column} AS grouping_value,
                    uniqExact(cert_hash) AS count
                FROM {self._qualified("cert_findings")}
                WHERE created_at >= %(cutoff)s
                  AND {source_column} != ''
                GROUP BY grouping_value
                ORDER BY count DESC
                LIMIT %(limit)s
                """,
                parameters={"cutoff": cutoff, "limit": limit},
            ).result_rows
        elif group_by == "registered_domain":
            rows = self.client.query(
                f"""
                SELECT
                    grouping_value,
                    count() AS count
                FROM
                (
                    SELECT DISTINCT
                        cert_hash,
                        {expr} AS grouping_value
                    FROM {self._qualified("observations")} AS o
                    WHERE o.seen_at >= %(cutoff)s
                )
                GROUP BY grouping_value
                ORDER BY count DESC
                LIMIT %(limit)s
                """,
                parameters={"cutoff": cutoff, "limit": limit},
            ).result_rows
        else:
            rows = self.client.query(
                f"""
                SELECT
                    grouping_value,
                    count() AS count
                FROM
                (
                    SELECT
                        cert_hash,
                        {expr} AS grouping_value
                    FROM
                    (
                        SELECT *
                        FROM {self._qualified("certificates")} FINAL
                    ) AS c
                    WHERE c.last_seen >= %(cutoff)s
                )
                GROUP BY grouping_value
                ORDER BY count DESC
                LIMIT %(limit)s
                """,
                parameters={"cutoff": cutoff, "limit": limit},
            ).result_rows
        return {
            "issuer": "godaddy",
            "days": days,
            "group_by": group_by,
            "label": label,
            "buckets": [
                {
                    "value": value,
                    "count": int(count),
                }
                for value, count in rows
            ],
        }

    def query_issuer_breakdown_range(
        self,
        group_by: str,
        date_from: date,
        date_to: date,
        limit: int,
    ) -> dict[str, Any]:
        start, end = self._range_bounds(date_from, date_to)
        groupings = {
            "issuer_cn": ("c.issuer_cn", "issuer_common_name"),
            "issuer_dn": ("c.issuer_dn", "issuer_distinguished_name"),
            "validation_type": (self._validation_type_expr(), "validation_type"),
            "sig_alg": ("c.sig_alg", "signature_algorithm"),
            "key_type": ("c.key_type", "key_type"),
            "key_size": ("toString(c.key_size)", "key_size"),
            "eku_set": ("if(length(c.eku) = 0, '(none)', arrayStringConcat(arraySort(c.eku), ','))", "eku_set"),
            "finding_code": ("f.finding_code", "finding_code"),
            "severity": ("f.severity", "severity"),
            "anomaly_bucket": (
                "multiIf(c.anomaly_score >= 60, '60+', c.anomaly_score >= 30, '30-59', c.anomaly_score >= 10, '10-29', '0-9')",
                "anomaly_bucket",
            ),
            "registered_domain": ("o.registered_domain", "registered_domain"),
            "validity_bucket": (
                "multiIf(c.validity_days <= 90, '0-90', c.validity_days <= 180, '91-180', c.validity_days <= 397, '181-397', '398+')",
                "validity_bucket",
            ),
            "san_count_bucket": (
                "multiIf(c.san_count = 1, '1', c.san_count <= 5, '2-5', c.san_count <= 25, '6-25', '26+')",
                "san_count_bucket",
            ),
        }
        if group_by not in groupings:
            raise ValueError(f"Unsupported group_by value: {group_by}")
        expr, label = groupings[group_by]
        if group_by in {"finding_code", "severity"}:
            source_column = "finding_code" if group_by == "finding_code" else "severity"
            rows = self.client.query(
                f"""
                SELECT
                    {source_column} AS grouping_value,
                    uniqExact(cert_hash) AS count
                FROM {self._qualified("cert_findings")}
                WHERE created_at >= %(start)s
                  AND created_at < %(end)s
                  AND {source_column} != ''
                GROUP BY grouping_value
                ORDER BY count DESC
                LIMIT %(limit)s
                """,
                parameters={"start": start, "end": end, "limit": limit},
            ).result_rows
        elif group_by == "registered_domain":
            rows = self.client.query(
                f"""
                SELECT grouping_value, count() AS count
                FROM
                (
                    SELECT DISTINCT
                        cert_hash,
                        {expr} AS grouping_value
                    FROM {self._qualified("observations")} AS o
                    WHERE o.seen_at >= %(start)s
                      AND o.seen_at < %(end)s
                )
                GROUP BY grouping_value
                ORDER BY count DESC
                LIMIT %(limit)s
                """,
                parameters={"start": start, "end": end, "limit": limit},
            ).result_rows
        else:
            rows = self.client.query(
                f"""
                SELECT grouping_value, count() AS count
                FROM
                (
                    SELECT
                        cert_hash,
                        {expr} AS grouping_value
                    FROM
                    (
                        SELECT *
                        FROM {self._qualified("certificates")} FINAL
                    ) AS c
                    WHERE c.last_seen >= %(start)s
                      AND c.last_seen < %(end)s
                )
                GROUP BY grouping_value
                ORDER BY count DESC
                LIMIT %(limit)s
                """,
                parameters={"start": start, "end": end, "limit": limit},
            ).result_rows
        return {
            "issuer": "godaddy",
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "group_by": group_by,
            "label": label,
            "buckets": [{"value": value, "count": int(count)} for value, count in rows],
        }

    def query_anomalies(self, days: int, limit: int) -> list[dict[str, Any]]:
        cutoff = datetime.now(tz=UTC) - timedelta(days=days)
        try:
            cert_rows = self.client.query(
                f"""
                SELECT
                    c.cert_hash,
                    c.subject_cn,
                    c.dns_names,
                    JSONExtractUInt(anomaly.evidence_json, 'anomaly_score') AS anomaly_score,
                    c.last_seen,
                    anomaly.evidence_json
                FROM
                (
                    SELECT
                        cert_hash,
                        evidence_json,
                        created_at,
                        row_number() OVER (PARTITION BY cert_hash ORDER BY created_at DESC) AS row_num
                    FROM {self._qualified("cert_findings")}
                    WHERE finding_code = 'ANOMALY_SCORE'
                      AND created_at >= %(cutoff)s
                ) AS anomaly
                INNER JOIN {self._qualified("certificates")} AS c
                    ON c.cert_hash = anomaly.cert_hash
                WHERE anomaly.row_num = 1
                  AND c.last_seen >= %(cutoff)s
                  AND JSONExtractUInt(anomaly.evidence_json, 'anomaly_score') > 0
                ORDER BY anomaly_score DESC, last_seen DESC
                LIMIT %(limit)s
                """,
                parameters={"cutoff": cutoff, "limit": limit},
            ).result_rows
        except Exception as exc:
            if "MEMORY_LIMIT_EXCEEDED" not in str(exc):
                raise
            LOGGER.warning("Primary anomaly query exceeded memory; using certificate-score fallback.")
            cert_rows = self.client.query(
                f"""
                SELECT
                    cert_hash,
                    subject_cn,
                    dns_names,
                    anomaly_score,
                    last_seen,
                    '' AS evidence_json
                FROM {self._qualified("certificates")}
                WHERE last_seen >= %(cutoff)s
                  AND anomaly_score > 0
                ORDER BY anomaly_score DESC, last_seen DESC
                LIMIT %(limit)s
                """,
                parameters={"cutoff": cutoff, "limit": limit},
            ).result_rows
        cert_hashes = [str(row[0]) for row in cert_rows]
        anomaly_evidence_by_hash: dict[str, dict[str, Any]] = {}
        if cert_hashes:
            quoted_hashes = self._quoted_string_list(cert_hashes)
            anomaly_rows = self.client.query(
                f"""
                SELECT cert_hash, evidence_json
                FROM
                (
                    SELECT
                        cert_hash,
                        evidence_json,
                        created_at,
                        row_number() OVER (PARTITION BY cert_hash ORDER BY created_at DESC) AS row_num
                    FROM {self._qualified("cert_findings")}
                    WHERE finding_code = 'ANOMALY_SCORE'
                      AND cert_hash IN ({quoted_hashes})
                )
                WHERE row_num = 1
                """
            ).result_rows
            anomaly_evidence_by_hash = {
                str(cert_hash): json.loads(evidence_json) if evidence_json else {"top_signals": []}
                for cert_hash, evidence_json in anomaly_rows
            }
            finding_rows = self.client.query(
                f"""
                SELECT cert_hash, severity, count() AS count
                FROM {self._qualified("cert_findings")}
                WHERE created_at >= %(cutoff)s
                  AND finding_code != 'ANOMALY_SCORE'
                  AND cert_hash IN ({quoted_hashes})
                GROUP BY cert_hash, severity
                """,
                parameters={"cutoff": cutoff},
            ).result_rows
        else:
            finding_rows = []
        severity_counts: dict[str, dict[str, int]] = defaultdict(dict)
        for cert_hash, severity, count in finding_rows:
            severity_counts[str(cert_hash)][str(severity)] = int(count)

        results: list[dict[str, Any]] = []
        for cert_hash, subject_cn, dns_names, anomaly_score, _last_seen, evidence_json in cert_rows:
            evidence = anomaly_evidence_by_hash.get(str(cert_hash))
            if evidence is None:
                evidence = json.loads(evidence_json) if evidence_json else {"top_signals": []}
            dns_name_list = list(dns_names)[:5]
            results.append(
                {
                    "cert_hash": cert_hash,
                    "subject_cn": subject_cn,
                    "dns_names": dns_name_list,
                    "dns_names_unicode": [to_unicode_hostname(name) for name in dns_name_list],
                    "anomaly_score": int(anomaly_score),
                    "top_signals": evidence.get("top_signals", []),
                    "evidence": evidence,
                    "finding_severity_counts": severity_counts.get(str(cert_hash), {}),
                }
            )
        return results

    def query_anomalies_range(self, date_from: date, date_to: date, limit: int) -> list[dict[str, Any]]:
        start, end = self._range_bounds(date_from, date_to)
        try:
            cert_rows = self.client.query(
                f"""
                SELECT
                    c.cert_hash,
                    c.subject_cn,
                    c.dns_names,
                    JSONExtractUInt(anomaly.evidence_json, 'anomaly_score') AS anomaly_score,
                    c.last_seen,
                    anomaly.evidence_json
                FROM
                (
                    SELECT
                        cert_hash,
                        evidence_json,
                        created_at,
                        row_number() OVER (PARTITION BY cert_hash ORDER BY created_at DESC) AS row_num
                    FROM {self._qualified("cert_findings")}
                    WHERE finding_code = 'ANOMALY_SCORE'
                      AND created_at >= %(start)s
                      AND created_at < %(end)s
                ) AS anomaly
                INNER JOIN {self._qualified("certificates")} AS c
                    ON c.cert_hash = anomaly.cert_hash
                WHERE anomaly.row_num = 1
                  AND c.last_seen >= %(start)s
                  AND c.last_seen < %(end)s
                  AND JSONExtractUInt(anomaly.evidence_json, 'anomaly_score') > 0
                ORDER BY anomaly_score DESC, last_seen DESC
                LIMIT %(limit)s
                """,
                parameters={"start": start, "end": end, "limit": limit},
            ).result_rows
        except Exception as exc:
            if "MEMORY_LIMIT_EXCEEDED" not in str(exc):
                raise
            LOGGER.warning("Primary anomaly range query exceeded memory; using certificate-score fallback.")
            cert_rows = self.client.query(
                f"""
                SELECT
                    cert_hash,
                    subject_cn,
                    dns_names,
                    anomaly_score,
                    last_seen,
                    '' AS evidence_json
                FROM {self._qualified("certificates")}
                WHERE last_seen >= %(start)s
                  AND last_seen < %(end)s
                  AND anomaly_score > 0
                ORDER BY anomaly_score DESC, last_seen DESC
                LIMIT %(limit)s
                """,
                parameters={"start": start, "end": end, "limit": limit},
            ).result_rows
        cert_hashes = [str(row[0]) for row in cert_rows]
        anomaly_evidence_by_hash: dict[str, dict[str, Any]] = {}
        if cert_hashes:
            quoted_hashes = self._quoted_string_list(cert_hashes)
            anomaly_rows = self.client.query(
                f"""
                SELECT cert_hash, evidence_json
                FROM
                (
                    SELECT
                        cert_hash,
                        evidence_json,
                        created_at,
                        row_number() OVER (PARTITION BY cert_hash ORDER BY created_at DESC) AS row_num
                    FROM {self._qualified("cert_findings")}
                    WHERE finding_code = 'ANOMALY_SCORE'
                      AND cert_hash IN ({quoted_hashes})
                )
                WHERE row_num = 1
                """
            ).result_rows
            anomaly_evidence_by_hash = {
                str(cert_hash): json.loads(evidence_json) if evidence_json else {"top_signals": []}
                for cert_hash, evidence_json in anomaly_rows
            }
            finding_rows = self.client.query(
                f"""
                SELECT cert_hash, severity, count() AS count
                FROM {self._qualified("cert_findings")}
                WHERE created_at >= %(start)s
                  AND created_at < %(end)s
                  AND finding_code != 'ANOMALY_SCORE'
                  AND cert_hash IN ({quoted_hashes})
                GROUP BY cert_hash, severity
                """,
                parameters={"start": start, "end": end},
            ).result_rows
        else:
            finding_rows = []
        severity_counts: dict[str, dict[str, int]] = defaultdict(dict)
        for cert_hash, severity, count in finding_rows:
            severity_counts[str(cert_hash)][str(severity)] = int(count)

        results: list[dict[str, Any]] = []
        for cert_hash, subject_cn, dns_names, anomaly_score, _last_seen, evidence_json in cert_rows:
            evidence = anomaly_evidence_by_hash.get(str(cert_hash))
            if evidence is None:
                evidence = json.loads(evidence_json) if evidence_json else {"top_signals": []}
            dns_name_list = list(dns_names)[:5]
            results.append(
                {
                    "cert_hash": cert_hash,
                    "subject_cn": subject_cn,
                    "dns_names": dns_name_list,
                    "dns_names_unicode": [to_unicode_hostname(name) for name in dns_name_list],
                    "anomaly_score": int(anomaly_score),
                    "top_signals": evidence.get("top_signals", []),
                    "evidence": evidence,
                    "finding_severity_counts": severity_counts.get(str(cert_hash), {}),
                }
            )
        return results

    def query_findings_summary_range(self, date_from: date, date_to: date, limit: int) -> dict[str, Any]:
        start, end = self._range_bounds(date_from, date_to)
        rows = self.client.query(
            f"""
            SELECT
                finding_code,
                severity,
                uniqExact(cert_hash) AS cert_count
            FROM {self._qualified("cert_findings")}
            WHERE created_at >= %(start)s
              AND created_at < %(end)s
              AND finding_code != 'ANOMALY_SCORE'
            GROUP BY finding_code, severity
            ORDER BY cert_count DESC, finding_code ASC
            LIMIT %(limit)s
            """,
            parameters={"start": start, "end": end, "limit": limit},
        ).result_rows
        severity_totals = self.client.query(
            f"""
            SELECT severity, uniqExact(cert_hash) AS cert_count
            FROM {self._qualified("cert_findings")}
            WHERE created_at >= %(start)s
              AND created_at < %(end)s
              AND finding_code != 'ANOMALY_SCORE'
            GROUP BY severity
            ORDER BY cert_count DESC
            """,
            parameters={"start": start, "end": end},
        ).result_rows
        return {
            "issuer": "godaddy",
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "severity_totals": {severity: int(count) for severity, count in severity_totals},
            "findings": [
                {"finding_code": finding_code, "severity": severity, "cert_count": int(cert_count)}
                for finding_code, severity, cert_count in rows
            ],
        }

    def get_certificate_details(self, cert_hash: str) -> dict[str, Any] | None:
        cert_row = self.client.query(
            f"""
            SELECT *
            FROM {self._qualified("certificates")} FINAL
            WHERE cert_hash = %(cert_hash)s
            LIMIT 1
            """,
            parameters={"cert_hash": cert_hash},
        )
        if not cert_row.result_rows:
            return None

        certificate = dict(zip(cert_row.column_names, cert_row.result_rows[0]))
        certificate["validation_type"] = validation_type_from_policy_oids(certificate.get("policy_oids", []))
        finding_rows = self.client.query(
            f"""
            SELECT finding_code, severity, evidence_json, created_at
            FROM {self._qualified("cert_findings")}
            WHERE cert_hash = %(cert_hash)s
            ORDER BY created_at DESC
            LIMIT 100
            """,
            parameters={"cert_hash": cert_hash},
        ).result_rows
        findings = [
            {
                "finding_code": finding_code,
                "severity": severity,
                "evidence": json.loads(evidence_json),
                "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
            }
            for finding_code, severity, evidence_json, created_at in finding_rows
        ]
        certificate["dns_names_unicode"] = [to_unicode_hostname(name) for name in certificate.get("dns_names", [])]
        certificate["findings"] = findings
        return certificate

    def search_recent_certificates(
        self,
        *,
        days: int,
        limit: int,
        registered_domain: str | None = None,
        validation_type: str | None = None,
        subject_cn_contains: str | None = None,
        issuer_contains: str | None = None,
        eku_contains: str | None = None,
        finding_code: str | None = None,
        finding_code_contains: str | None = None,
        has_wildcard: bool | None = None,
        has_punycode: bool | None = None,
        min_validity_days: int | None = None,
        max_validity_days: int | None = None,
        min_anomaly_score: int | None = None,
    ) -> list[dict[str, Any]]:
        cutoff = datetime.now(tz=UTC) - timedelta(days=days)
        where_clauses = ["o.seen_at >= %(cutoff)s"]
        parameters: dict[str, Any] = {"cutoff": cutoff, "limit": limit}
        if registered_domain:
            where_clauses.append("o.registered_domain = %(registered_domain)s")
            parameters["registered_domain"] = registered_domain
        if validation_type:
            where_clauses.append(f"{self._validation_type_expr()} = %(validation_type)s")
            parameters["validation_type"] = validation_type
        if subject_cn_contains:
            where_clauses.append("positionCaseInsensitive(c.subject_cn, %(subject_cn_contains)s) > 0")
            parameters["subject_cn_contains"] = subject_cn_contains
        if issuer_contains:
            where_clauses.append("positionCaseInsensitive(c.issuer_dn, %(issuer_contains)s) > 0")
            parameters["issuer_contains"] = issuer_contains
        if eku_contains:
            where_clauses.append(
                "arrayExists(eku_value -> positionCaseInsensitive(eku_value, %(eku_contains)s) > 0, c.eku)"
            )
            parameters["eku_contains"] = eku_contains
        if finding_code:
            where_clauses.append(
                "c.cert_hash IN (SELECT cert_hash FROM {findings} WHERE finding_code = %(finding_code)s)".format(
                    findings=self._qualified("cert_findings")
                )
            )
            parameters["finding_code"] = finding_code
        if finding_code_contains:
            where_clauses.append(
                "c.cert_hash IN (SELECT cert_hash FROM {findings} WHERE positionCaseInsensitive(finding_code, %(finding_code_contains)s) > 0)".format(
                    findings=self._qualified("cert_findings")
                )
            )
            parameters["finding_code_contains"] = finding_code_contains
        if has_wildcard is not None:
            where_clauses.append("c.has_wildcard = %(has_wildcard)s")
            parameters["has_wildcard"] = int(has_wildcard)
        if has_punycode is not None:
            where_clauses.append("c.has_punycode = %(has_punycode)s")
            parameters["has_punycode"] = int(has_punycode)
        if min_validity_days is not None:
            where_clauses.append("c.validity_days >= %(min_validity_days)s")
            parameters["min_validity_days"] = min_validity_days
        if max_validity_days is not None:
            where_clauses.append("c.validity_days <= %(max_validity_days)s")
            parameters["max_validity_days"] = max_validity_days
        if min_anomaly_score is not None:
            where_clauses.append("c.anomaly_score >= %(min_anomaly_score)s")
            parameters["min_anomaly_score"] = min_anomaly_score

        rows = self.client.query(
            f"""
            SELECT
                c.cert_hash,
                c.subject_cn,
                c.issuer_dn,
                c.dns_names,
                c.eku,
                {self._validation_type_expr()} AS validation_type,
                c.validity_days,
                c.has_wildcard,
                c.has_punycode,
                c.anomaly_score,
                max(o.seen_at) AS last_seen,
                any(o.registered_domain) AS registered_domain
            FROM {self._qualified("observations")} AS o
            INNER JOIN (SELECT * FROM {self._qualified("certificates")} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            WHERE {' AND '.join(where_clauses)}
            GROUP BY
                c.cert_hash,
                c.subject_cn,
                c.issuer_dn,
                c.dns_names,
                c.eku,
                validation_type,
                c.validity_days,
                c.has_wildcard,
                c.has_punycode,
                c.anomaly_score
            ORDER BY last_seen DESC, c.anomaly_score DESC
            LIMIT %(limit)s
            """,
            parameters=parameters,
        ).result_rows
        return [
            {
                "cert_hash": cert_hash,
                "subject_cn": subject_cn,
                "issuer_dn": issuer_dn,
                "dns_names": list(dns_names)[:10],
                "eku": list(eku_values),
                "validation_type": validation_type,
                "validity_days": int(validity_days),
                "has_wildcard": bool(has_wildcard_value),
                "has_punycode": bool(has_punycode_value),
                "anomaly_score": int(anomaly_score),
                "last_seen": last_seen.isoformat() if hasattr(last_seen, "isoformat") else str(last_seen),
                "registered_domain": registered_domain_value,
            }
            for (
                cert_hash,
                subject_cn,
                issuer_dn,
                dns_names,
                eku_values,
                validation_type,
                validity_days,
                has_wildcard_value,
                has_punycode_value,
                anomaly_score,
                last_seen,
                registered_domain_value,
            ) in rows
        ]

    def get_domain_activity(self, registered_domain: str, days: int, limit: int) -> dict[str, Any]:
        cutoff = datetime.now(tz=UTC) - timedelta(days=days)
        rows = self.client.query(
            f"""
            SELECT
                o.seen_at,
                c.cert_hash,
                c.subject_cn,
                c.dns_names,
                c.anomaly_score,
                c.issuer_dn,
                anyLast(anomaly.evidence_json) AS anomaly_evidence
            FROM {self._qualified("observations")} AS o
            INNER JOIN (SELECT * FROM {self._qualified("certificates")} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            LEFT JOIN {self._qualified("cert_findings")} AS anomaly
                ON anomaly.cert_hash = c.cert_hash
               AND anomaly.finding_code = 'ANOMALY_SCORE'
            WHERE o.registered_domain = %(registered_domain)s
              AND o.seen_at >= %(cutoff)s
            GROUP BY
                o.seen_at,
                c.cert_hash,
                c.subject_cn,
                c.dns_names,
                c.anomaly_score,
                c.issuer_dn
            ORDER BY o.seen_at DESC
            LIMIT %(limit)s
            """,
            parameters={"registered_domain": registered_domain, "cutoff": cutoff, "limit": limit},
        ).result_rows
        activity = []
        for seen_at, cert_hash, subject_cn, dns_names, anomaly_score, issuer_dn, anomaly_evidence in rows:
            evidence = json.loads(anomaly_evidence) if anomaly_evidence else {"top_signals": []}
            activity.append(
                {
                    "seen_at": seen_at.isoformat() if hasattr(seen_at, "isoformat") else str(seen_at),
                    "cert_hash": cert_hash,
                    "subject_cn": subject_cn,
                    "dns_names": list(dns_names)[:10],
                    "anomaly_score": int(anomaly_score),
                    "issuer_dn": issuer_dn,
                    "top_signals": evidence.get("top_signals", []),
                }
            )
        return {
            "registered_domain": registered_domain,
            "days": days,
            "activity": activity,
        }
