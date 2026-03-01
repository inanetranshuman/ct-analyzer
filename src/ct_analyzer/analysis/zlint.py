from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from ct_analyzer.cert.x509_features import FindingRecord
from ct_analyzer.config import Settings


LOGGER = logging.getLogger(__name__)

RESULT_SEVERITY = {
    "fatal": "high",
    "error": "high",
    "warn": "medium",
    "notice": "low",
    "info": "info",
}
NON_FINDING_RESULTS = {"pass", "na", "ne", "not applicable", "not effective"}


def _normalize_code(name: str) -> str:
    return "ZLINT_" + "".join(ch if ch.isalnum() else "_" for ch in name.upper())


def _extract_result_fields(result: Any) -> tuple[str, str, str | None]:
    if isinstance(result, dict):
        status = str(result.get("result") or result.get("status") or "").lower()
        details = str(result.get("details") or result.get("detail") or "")
        source = result.get("source")
        return status, details, str(source) if source is not None else None
    status = str(result).lower()
    return status, "", None


@lru_cache(maxsize=1)
def _zlint_version(bin_path: str) -> str:
    try:
        completed = subprocess.run(
            [bin_path, "-version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return "unknown"
    value = (completed.stdout or completed.stderr or "").strip()
    return value or "unknown"


def zlint_available(settings: Settings) -> bool:
    if not settings.zlint.enabled:
        return False
    return shutil.which(settings.zlint.bin_path) is not None


def run_zlint(cert_der: bytes, cert_hash: str, settings: Settings) -> list[FindingRecord]:
    if not settings.zlint.enabled:
        return []

    bin_path = shutil.which(settings.zlint.bin_path)
    if not bin_path:
        LOGGER.warning("ZLint enabled but binary '%s' was not found", settings.zlint.bin_path)
        return []

    temp_path: Path | None = None
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_der)
        with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as handle:
            temp_path = Path(handle.name)
            handle.write(cert.public_bytes(serialization.Encoding.PEM))

        command = [bin_path, *settings.zlint.args, str(temp_path)]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=settings.zlint.timeout_seconds,
        )
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        if completed.returncode != 0 and not stdout:
            LOGGER.warning("ZLint failed for %s: %s", cert_hash, stderr or f"exit {completed.returncode}")
            return []

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            LOGGER.warning("ZLint returned non-JSON output for %s", cert_hash)
            return []

        results = payload.get("results") if isinstance(payload, dict) and "results" in payload else payload
        if not isinstance(results, dict):
            LOGGER.warning("ZLint JSON did not contain a results object for %s", cert_hash)
            return []

        created_at = datetime.now(tz=UTC)
        version = _zlint_version(bin_path)
        findings: list[FindingRecord] = []
        for lint_name, result in results.items():
            status, details, source = _extract_result_fields(result)
            if not status or status in NON_FINDING_RESULTS:
                continue
            findings.append(
                FindingRecord(
                    cert_hash=cert_hash,
                    finding_code=_normalize_code(str(lint_name)),
                    severity=RESULT_SEVERITY.get(status, "low"),
                    evidence_json=json.dumps(
                        {
                            "zlint_name": lint_name,
                            "zlint_result": status,
                            "details": details,
                            "source": source,
                            "zlint_version": version,
                        },
                        sort_keys=True,
                    ),
                    created_at=created_at,
                )
            )
        return findings
    except subprocess.TimeoutExpired:
        LOGGER.warning("ZLint timed out for %s after %ss", cert_hash, settings.zlint.timeout_seconds)
        return []
    except Exception:
        LOGGER.exception("ZLint execution failed for %s", cert_hash)
        return []
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                LOGGER.debug("Failed to remove temporary zlint file %s", temp_path)
