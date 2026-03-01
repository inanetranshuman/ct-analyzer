from __future__ import annotations

import argparse
import asyncio
import json
import logging

from ct_analyzer.api.server import run_api
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
    return parser


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
