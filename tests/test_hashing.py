from pathlib import Path

from cryptography.hazmat.primitives import serialization

from ct_analyzer.cert.fingerprint import cert_sha256_hex
from ct_analyzer.cert.parse import load_certificate_from_pem


def test_cert_hash_stable_from_der() -> None:
    pem = Path("tests/fixtures/good_rsa.pem").read_bytes()
    cert = load_certificate_from_pem(pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    assert cert_sha256_hex(der) == cert_sha256_hex(der)
