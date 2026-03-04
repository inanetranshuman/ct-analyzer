from datetime import UTC, datetime

from ct_analyzer.analysis.anomalies import analyze_certificate
from ct_analyzer.analysis.lint import lint_certificate
from ct_analyzer.cert.x509_features import CertificateMetadata
from ct_analyzer.config import Settings


def _metadata(subject_org: str, dns_name: str, validation_type: str = "OV") -> CertificateMetadata:
    now = datetime.now(tz=UTC)
    return CertificateMetadata(
        cert_hash="hash",
        subject_cn=dns_name,
        subject_dn=f"CN={dns_name},O={subject_org}" if subject_org else f"CN={dns_name}",
        subject_org=subject_org,
        issuer_cn="Go Daddy Secure Certificate Authority - G2",
        issuer_dn="CN=Go Daddy Secure Certificate Authority - G2",
        issuer_spki_hash="issuer-spki",
        serial_number="0x1",
        not_before=now,
        not_after=now,
        dns_names=[dns_name],
        san_count=1,
        has_wildcard=0,
        has_punycode=0,
        validity_days=90,
        key_type="RSA",
        key_size=2048,
        sig_alg="SHA256",
        eku=["serverAuth"],
        key_usage=["digitalSignature", "keyEncipherment"],
        basic_constraints_ca=0,
        ski=None,
        aki=None,
        policy_oids=[],
        aia_ocsp_urls=[],
        crl_dp_urls=[],
        validation_type=validation_type,
        has_must_staple=0,
        has_ip_san=0,
        has_uri_san=0,
        has_email_san=0,
        subject_has_non_ascii=0,
        issuer_has_non_ascii=0,
        subject_dn_length=20,
        issuer_dn_length=20,
        first_seen=now,
        last_seen=now,
    )


def test_org_domain_mismatch_and_brand_impersonation_are_flagged() -> None:
    metadata = _metadata("Microsoft Corporation", "secure-login-example.net")
    settings = Settings()

    finding_codes = {finding.finding_code for finding in lint_certificate(metadata, settings)}
    assert "ORG_DOMAIN_MISMATCH" in finding_codes
    assert "ORG_BRAND_IMPERSONATION" in finding_codes

    _score, top_signals, _finding = analyze_certificate(metadata, settings)
    signal_codes = {signal.code for signal in top_signals}
    assert "org_domain_mismatch" in signal_codes
    assert "brand_org_impersonation" in signal_codes
