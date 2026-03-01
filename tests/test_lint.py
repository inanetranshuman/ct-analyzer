from pathlib import Path

from cryptography.hazmat.primitives import serialization

from ct_analyzer.analysis.lint import lint_certificate
from ct_analyzer.cert.fingerprint import cert_sha256_hex
from ct_analyzer.cert.parse import load_certificate_from_pem
from ct_analyzer.cert.x509_features import extract_certificate_metadata
from ct_analyzer.config import Settings


def test_lint_flags_weak_rsa_and_missing_san() -> None:
    pem = Path("tests/fixtures/weak_rsa.pem").read_bytes()
    cert = load_certificate_from_pem(pem)
    metadata = extract_certificate_metadata(
        cert=cert,
        cert_hash=cert_sha256_hex(cert.public_bytes(encoding=serialization.Encoding.DER)),
        seen_at=cert.not_valid_before_utc,
    )
    findings = {finding.finding_code for finding in lint_certificate(metadata, Settings())}
    assert "SAN_MISSING" in findings
    assert "RSA_KEY_TOO_SMALL" in findings
    assert "LEAF_KEY_USAGE_CA_BITS" in findings
