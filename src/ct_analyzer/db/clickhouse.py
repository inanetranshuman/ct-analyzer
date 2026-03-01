from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

import clickhouse_connect

from ct_analyzer.analysis.baseline import IssuerBaseline
from ct_analyzer.config import Settings
from ct_analyzer.db.migrations import load_schema_sql


LOGGER = logging.getLogger(__name__)


class ClickHouseRepository:
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

    def _new_client(self):
        return clickhouse_connect.get_client(
            host=self.settings.clickhouse.host,
            port=self.settings.clickhouse.port,
            username=self.settings.clickhouse.user,
            password=self.settings.clickhouse.password,
            database="default",
        )

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
        self.client.insert(self._qualified(table), payload, column_names=columns)

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
        parameters = {"cutoff": datetime.now(tz=UTC) - timedelta(days=days), "updated_at": updated_at}
        self.client.command(daily_query, parameters=parameters)
        self.client.command(sigalg_query, parameters=parameters)

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
        }

    def query_anomalies(self, days: int, limit: int) -> list[dict[str, Any]]:
        cutoff = datetime.now(tz=UTC) - timedelta(days=days)
        cert_rows = self.client.query(
            f"""
            SELECT
                c.cert_hash,
                c.subject_cn,
                c.dns_names,
                c.anomaly_score,
                max(o.seen_at) AS last_seen,
                anyLast(anomaly.evidence_json) AS anomaly_evidence
            FROM {self._qualified("observations")} AS o
            INNER JOIN (SELECT * FROM {self._qualified("certificates")} FINAL) AS c
                ON c.cert_hash = o.cert_hash
            LEFT JOIN {self._qualified("cert_findings")} AS anomaly
                ON anomaly.cert_hash = c.cert_hash
               AND anomaly.finding_code = 'ANOMALY_SCORE'
            WHERE o.seen_at >= %(cutoff)s
              AND c.anomaly_score > 0
            GROUP BY c.cert_hash, c.subject_cn, c.dns_names, c.anomaly_score
            ORDER BY c.anomaly_score DESC, last_seen DESC
            LIMIT %(limit)s
            """,
            parameters={"cutoff": cutoff, "limit": limit},
        ).result_rows
        finding_rows = self.client.query(
            f"""
            SELECT cert_hash, severity, count() AS count
            FROM {self._qualified("cert_findings")}
            WHERE created_at >= %(cutoff)s
              AND finding_code != 'ANOMALY_SCORE'
            GROUP BY cert_hash, severity
            """,
            parameters={"cutoff": cutoff},
        ).result_rows
        severity_counts: dict[str, dict[str, int]] = defaultdict(dict)
        for cert_hash, severity, count in finding_rows:
            severity_counts[str(cert_hash)][str(severity)] = int(count)

        results: list[dict[str, Any]] = []
        for cert_hash, subject_cn, dns_names, anomaly_score, _last_seen, anomaly_evidence in cert_rows:
            evidence = json.loads(anomaly_evidence) if anomaly_evidence else {"top_signals": []}
            results.append(
                {
                    "cert_hash": cert_hash,
                    "subject_cn": subject_cn,
                    "dns_names": list(dns_names)[:5],
                    "anomaly_score": int(anomaly_score),
                    "top_signals": evidence.get("top_signals", []),
                    "evidence": evidence,
                    "finding_severity_counts": severity_counts.get(str(cert_hash), {}),
                }
            )
        return results
