from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography import x509

from ct_analyzer.config import IssuerMatchingSettings


def load_certificate_from_der(der_bytes: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der_bytes)


def load_certificate_from_pem(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes)


def parse_certstream_message(raw_message: str) -> dict[str, Any]:
    payload = json.loads(raw_message)
    if payload.get("message_type") != "certificate_update":
        return {}
    return payload


def decode_leaf_der(payload: dict[str, Any]) -> bytes | None:
    leaf_cert = payload.get("data", {}).get("leaf_cert", {})
    for key in ("as_der", "der", "cert"):
        value = leaf_cert.get(key)
        if value:
            return base64.b64decode(value)
    return None


def decode_chain(payload: dict[str, Any]) -> list[x509.Certificate]:
    chain_items = payload.get("data", {}).get("chain", [])
    certificates: list[x509.Certificate] = []
    for item in chain_items:
        for key in ("as_der", "der", "cert"):
            value = item.get(key)
            if value:
                certificates.append(load_certificate_from_der(base64.b64decode(value)))
                break
    return certificates


def message_seen_at(payload: dict[str, Any]) -> datetime:
    raw = payload.get("data", {}).get("seen")
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=UTC)
    return datetime.now(tz=UTC)


def log_id_from_payload(payload: dict[str, Any]) -> str:
    data = payload.get("data", {})
    return str(data.get("source", {}).get("name") or data.get("source", {}).get("url") or "certstream")


def hashed_issuer_key(issuer_dn: str) -> str:
    return hashlib.sha256(issuer_dn.encode("utf-8")).hexdigest()


def issuer_key(issuer_dn: str, issuer_spki_hash: str | None) -> str:
    return issuer_spki_hash or hashed_issuer_key(issuer_dn)


def issuer_matches(
    issuer_dn: str,
    issuer_spki_hash: str | None,
    settings: IssuerMatchingSettings,
) -> bool:
    dn_match = any(substring.lower() in issuer_dn.lower() for substring in settings.issuer_substrings)
    spki_match = issuer_spki_hash in set(settings.issuer_spki_hashes) if issuer_spki_hash else False
    if settings.match_mode == "issuer_dn":
        return dn_match
    if settings.match_mode == "issuer_spki":
        return spki_match
    return dn_match or spki_match
