from __future__ import annotations

import argparse
import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta

from ct_analyzer.analysis.anomalies import analyze_certificate
from ct_analyzer.api.server import run_api
from ct_analyzer.cert.domains import get_registered_domain
from ct_analyzer.cert.parse import issuer_key
from ct_analyzer.cert.x509_features import CertificateMetadata
from ct_analyzer.config import get_settings
from ct_analyzer.db.clickhouse import ClickHouseRepository
from ct_analyzer.db.rollups import refresh_rollups
from ct_analyzer.ingest.pipeline import IngestionPipeline
from ct_analyzer.mcp_server import create_mcp_server, mcp_dependency_error


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _require_supported_issuer(issuer: str) -> None:
    if issuer.lower() != "godaddy":
        raise SystemExit("Only the 'godaddy' issuer family is supported in the MVP.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ct-analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("migrate")
    subparsers.add_parser("ingest")
    subparsers.add_parser("api")
    subparsers.add_parser("mcp")

    rollup = subparsers.add_parser("rollup")
    rollup.add_argument("--days", type=int, default=30)

    stats = subparsers.add_parser("query-issuer-stats")
    stats.add_argument("--issuer", default="godaddy")
    stats.add_argument("--days", type=int, default=30)

    anomalies = subparsers.add_parser("query-anomalies")
    anomalies.add_argument("--issuer", default="godaddy")
    anomalies.add_argument("--days", type=int, default=7)
    anomalies.add_argument("--limit", type=int, default=50)

    rescore = subparsers.add_parser("rescore-anomalies")
    rescore.add_argument("--days", type=int, default=30)
    rescore.add_argument("--limit", type=int, default=50000)
    rescore.add_argument(
        "--all-certs",
        action="store_true",
        help="Recompute for all certs in the window instead of only currently non-zero anomaly scores.",
    )
    return parser


def _rescore_anomalies(repository: ClickHouseRepository, days: int, limit: int, all_certs: bool) -> None:
    cutoff = datetime.now(tz=UTC) - timedelta(days=days)
    score_filter = "" if all_certs else "AND anomaly_score > 0"
    rows = repository.client.query(
        f"""
        SELECT
            cert_hash,
            subject_cn,
            subject_dn,
            subject_org,
            issuer_cn,
            issuer_dn,
            issuer_spki_hash,
            serial_number,
            not_before,
            not_after,
            dns_names,
            san_count,
            has_wildcard,
            has_punycode,
            validity_days,
            key_type,
            key_size,
            sig_alg,
            eku,
            key_usage,
            basic_constraints_ca,
            ski,
            aki,
            policy_oids,
            aia_ocsp_urls,
            crl_dp_urls,
            validation_type,
            has_must_staple,
            has_ip_san,
            has_uri_san,
            has_email_san,
            subject_has_non_ascii,
            issuer_has_non_ascii,
            subject_dn_length,
            issuer_dn_length,
            first_seen,
            last_seen
        FROM {repository._qualified("certificates")}
        WHERE last_seen >= %(cutoff)s
          {score_filter}
        ORDER BY last_seen DESC
        LIMIT %(limit)s
        """,
        parameters={"cutoff": cutoff, "limit": limit},
    ).result_rows

    if not rows:
        print("No certificates matched rescore window.")
        return

    baseline_cache: dict[str, object] = {}
    findings_rows: list[dict[str, object]] = []
    now = datetime.now(tz=UTC)
    for row in rows:
        metadata = CertificateMetadata(
            cert_hash=str(row[0]),
            subject_cn=str(row[1] or ""),
            subject_dn=str(row[2] or ""),
            subject_org=str(row[3] or ""),
            issuer_cn=str(row[4] or ""),
            issuer_dn=str(row[5] or ""),
            issuer_spki_hash=str(row[6]) if row[6] else None,
            serial_number=str(row[7] or ""),
            not_before=row[8],
            not_after=row[9],
            dns_names=list(row[10] or []),
            san_count=int(row[11] or 0),
            has_wildcard=int(row[12] or 0),
            has_punycode=int(row[13] or 0),
            validity_days=int(row[14] or 0),
            key_type=str(row[15] or ""),
            key_size=int(row[16] or 0),
            sig_alg=str(row[17] or ""),
            eku=list(row[18] or []),
            key_usage=list(row[19] or []),
            basic_constraints_ca=int(row[20] or 0),
            ski=str(row[21]) if row[21] else None,
            aki=str(row[22]) if row[22] else None,
            policy_oids=list(row[23] or []),
            aia_ocsp_urls=list(row[24] or []),
            crl_dp_urls=list(row[25] or []),
            validation_type=str(row[26] or "Unknown"),
            has_must_staple=int(row[27] or 0),
            has_ip_san=int(row[28] or 0),
            has_uri_san=int(row[29] or 0),
            has_email_san=int(row[30] or 0),
            subject_has_non_ascii=int(row[31] or 0),
            issuer_has_non_ascii=int(row[32] or 0),
            subject_dn_length=int(row[33] or 0),
            issuer_dn_length=int(row[34] or 0),
            first_seen=row[35],
            last_seen=row[36],
        )

        issuer_key_value = issuer_key(metadata.issuer_dn, metadata.issuer_spki_hash)
        baseline = baseline_cache.get(issuer_key_value)
        if baseline is None:
            baseline = repository.fetch_issuer_baseline(issuer_key_value, days)
            baseline_cache[issuer_key_value] = baseline

        registered_domains = sorted({get_registered_domain(name) for name in metadata.dns_names if name})
        domain_burst_counts = repository.fetch_registered_domain_burst_counts(
            registered_domains,
            repository.settings.anomaly_thresholds.domain_burst_window_hours,
        )
        _, _, anomaly_finding = analyze_certificate(
            metadata,
            repository.settings,
            baseline=baseline,
            domain_burst_counts=domain_burst_counts,
        )
        anomaly_finding.created_at = now
        findings_rows.append(anomaly_finding.to_row())

    if findings_rows:
        repository.insert_findings(findings_rows)
    print(f"Inserted {len(findings_rows)} refreshed ANOMALY_SCORE findings for {len(rows)} certificates.")


def main() -> None:
    settings = get_settings()
    _configure_logging(settings.log_level)
    parser = build_parser()
    args = parser.parse_args()
    repository = ClickHouseRepository(settings)

    if args.command == "migrate":
        repository.migrate()
        return

    if args.command == "rollup":
        refresh_rollups(repository, args.days)
        return

    if args.command == "query-issuer-stats":
        _require_supported_issuer(args.issuer)
        print(json.dumps(repository.query_issuer_stats(args.days), indent=2, sort_keys=True))
        return

    if args.command == "query-anomalies":
        _require_supported_issuer(args.issuer)
        print(json.dumps(repository.query_anomalies(args.days, args.limit), indent=2, sort_keys=True))
        return

    if args.command == "rescore-anomalies":
        _rescore_anomalies(repository, args.days, args.limit, args.all_certs)
        return

    if args.command == "api":
        run_api(settings)
        return

    if args.command == "mcp":
        error = mcp_dependency_error()
        if error:
            raise SystemExit(error)
        create_mcp_server(lambda: repository, settings).run()
        return

    if args.command == "ingest":
        asyncio.run(IngestionPipeline(repository, settings).run())
