from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cert_sha256_hex(cert_der: bytes) -> str:
    return sha256_hex(cert_der)


def public_key_sha256_hex(cert: x509.Certificate) -> str:
    public_key_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_hex(public_key_der)
