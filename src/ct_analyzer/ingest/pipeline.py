from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ct_analyzer.analysis.anomalies import analyze_certificate
from ct_analyzer.analysis.baseline import BaselineCache
from ct_analyzer.analysis.lint import lint_certificate
from ct_analyzer.analysis.zlint import run_zlint
from ct_analyzer.cert.domains import get_registered_domain, tokenize_domain
from ct_analyzer.cert.fingerprint import cert_sha256_hex, public_key_sha256_hex
from ct_analyzer.cert.parse import (
    decode_chain,
    decode_leaf_der,
    issuer_key,
    issuer_matches,
    load_certificate_from_der,
    log_id_from_payload,
    message_seen_at,
)
from ct_analyzer.cert.x509_features import FindingRecord, ObservationRecord, extract_certificate_metadata
from ct_analyzer.config import Settings
from ct_analyzer.db.clickhouse import ClickHouseRepository
from ct_analyzer.ingest.certstream import stream_certstream_events


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class IngestStats:
    received_events: int = 0
    processed_events: int = 0
    matched_events: int = 0
    filtered_events: int = 0
    processing_errors: int = 0
    flushed_certificates: int = 0
    flushed_observations: int = 0
    flushed_findings: int = 0


def _build_observations(
    cert_hash: str,
    dns_names: list[str],
    seen_at: datetime,
    issuer_key_value: str,
    log_id: str,
) -> list[ObservationRecord]:
    grouped_tokens: dict[str, set[str]] = defaultdict(set)
    for dns_name in dns_names:
        registered_domain = get_registered_domain(dns_name)
        if not registered_domain:
            continue
        grouped_tokens[registered_domain].update(tokenize_domain(dns_name))

    if not grouped_tokens:
        grouped_tokens[""] = set()

    return [
        ObservationRecord(
            seen_at=seen_at,
            cert_hash=cert_hash,
            registered_domain=registered_domain,
            issuer_key=issuer_key_value,
            log_id=log_id,
            source="certstream",
            domain_tokens=sorted(tokens),
        )
        for registered_domain, tokens in grouped_tokens.items()
    ]


def _finding_rows(findings: Iterable[FindingRecord]) -> list[dict[str, Any]]:
    return [finding.to_row() for finding in findings]


class IngestionPipeline:
    def __init__(self, repository: ClickHouseRepository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings
        self.baselines = BaselineCache(repository)
        self.stats = IngestStats()

    async def run(self) -> None:
        incoming: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self.settings.ingest.queue_size)
        processed: asyncio.Queue[dict[str, list[dict[str, Any]]]] = asyncio.Queue(maxsize=self.settings.ingest.queue_size)

        async with asyncio.TaskGroup() as task_group:
            task_group.create_task(self._reader(incoming))
            for worker_id in range(self.settings.ingest.workers):
                task_group.create_task(self._worker(worker_id, incoming, processed))
            task_group.create_task(self._writer(processed))
            task_group.create_task(self._progress_logger(incoming, processed))

    async def _reader(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async for payload in stream_certstream_events(self.settings):
            self.stats.received_events += 1
            await queue.put(payload)

    async def _worker(
        self,
        worker_id: int,
        source_queue: asyncio.Queue[dict[str, Any]],
        sink_queue: asyncio.Queue[dict[str, list[dict[str, Any]]]],
    ) -> None:
        LOGGER.info("Starting worker %s", worker_id)
        while True:
            payload = await source_queue.get()
            try:
                record = await self._process_payload(payload)
                if record is not None:
                    self.stats.matched_events += 1
                    await sink_queue.put(record)
                else:
                    self.stats.filtered_events += 1
                self.stats.processed_events += 1
            except Exception:
                self.stats.processing_errors += 1
                LOGGER.exception("Failed to process certstream event")
            finally:
                source_queue.task_done()

    async def _process_payload(self, payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]] | None:
        leaf_der = decode_leaf_der(payload)
        if leaf_der is None:
            return None

        seen_at = message_seen_at(payload)
        log_id = log_id_from_payload(payload)
        chain = await asyncio.to_thread(decode_chain, payload)
        leaf_cert = await asyncio.to_thread(load_certificate_from_der, leaf_der)
        issuer_spki_hash = public_key_sha256_hex(chain[0]) if chain else None
        metadata = extract_certificate_metadata(
            cert=leaf_cert,
            cert_hash=cert_sha256_hex(leaf_der),
            seen_at=seen_at,
            issuer_spki_hash=issuer_spki_hash,
        )
        if not issuer_matches(metadata.issuer_dn, metadata.issuer_spki_hash, self.settings.matching):
            return None

        issuer_key_value = issuer_key(metadata.issuer_dn, metadata.issuer_spki_hash)
        baseline = await self.baselines.get(issuer_key_value, self.settings.window_days)
        _, _, anomaly_finding = analyze_certificate(metadata, self.settings, baseline=baseline)
        lint_findings = lint_certificate(metadata, self.settings)
        zlint_findings = await asyncio.to_thread(run_zlint, leaf_der, metadata.cert_hash, self.settings)
        observations = _build_observations(
            cert_hash=metadata.cert_hash,
            dns_names=metadata.dns_names,
            seen_at=seen_at,
            issuer_key_value=issuer_key_value,
            log_id=log_id,
        )
        return {
            "certificates": [metadata.to_row()],
            "observations": [observation.to_row() for observation in observations],
            "findings": _finding_rows([*lint_findings, *zlint_findings, anomaly_finding]),
        }

    async def _writer(self, queue: asyncio.Queue[dict[str, list[dict[str, Any]]]]) -> None:
        batch_certs: list[dict[str, Any]] = []
        batch_observations: list[dict[str, Any]] = []
        batch_findings: list[dict[str, Any]] = []

        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=self.settings.ingest.flush_seconds)
                batch_certs.extend(item["certificates"])
                batch_observations.extend(item["observations"])
                batch_findings.extend(item["findings"])
                queue.task_done()
            except asyncio.TimeoutError:
                pass

            if len(batch_observations) >= self.settings.ingest.batch_size or (
                batch_observations and queue.empty()
            ):
                await asyncio.to_thread(self.repository.insert_certificates, batch_certs)
                await asyncio.to_thread(self.repository.insert_observations, batch_observations)
                await asyncio.to_thread(self.repository.insert_findings, batch_findings)
                self.stats.flushed_certificates += len(batch_certs)
                self.stats.flushed_observations += len(batch_observations)
                self.stats.flushed_findings += len(batch_findings)
                LOGGER.info(
                    "Flushed %s certificates, %s observations, %s findings (totals: matched=%s filtered=%s errors=%s observations=%s)",
                    len(batch_certs),
                    len(batch_observations),
                    len(batch_findings),
                    self.stats.matched_events,
                    self.stats.filtered_events,
                    self.stats.processing_errors,
                    self.stats.flushed_observations,
                )
                batch_certs.clear()
                batch_observations.clear()
                batch_findings.clear()

    async def _progress_logger(
        self,
        incoming: asyncio.Queue[dict[str, Any]],
        processed: asyncio.Queue[dict[str, list[dict[str, Any]]]],
    ) -> None:
        while True:
            await asyncio.sleep(30)
            LOGGER.info(
                "Progress: received=%s processed=%s matched=%s filtered=%s errors=%s incoming_queue=%s processed_queue=%s flushed_certs=%s flushed_obs=%s flushed_findings=%s",
                self.stats.received_events,
                self.stats.processed_events,
                self.stats.matched_events,
                self.stats.filtered_events,
                self.stats.processing_errors,
                incoming.qsize(),
                processed.qsize(),
                self.stats.flushed_certificates,
                self.stats.flushed_observations,
                self.stats.flushed_findings,
            )
