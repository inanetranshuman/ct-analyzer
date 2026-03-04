from datetime import UTC, datetime

from ct_analyzer.analysis.anomalies import analyze_certificate
from ct_analyzer.cert.x509_features import CertificateMetadata
from ct_analyzer.config import Settings


def _metadata() -> CertificateMetadata:
    now = datetime.now(tz=UTC)
    return CertificateMetadata(
        cert_hash="hash",
        subject_cn="login.example.com",
        subject_dn="CN=login.example.com",
        issuer_cn="Go Daddy Secure Certificate Authority - G2",
        issuer_dn="CN=Go Daddy Secure Certificate Authority - G2",
        issuer_spki_hash="issuer-spki",
        serial_number="0x1",
        not_before=now,
        not_after=now,
        dns_names=["login.example.com"],
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


def test_registered_domain_burst_signal_added_for_repeated_domain_issuance() -> None:
    metadata = _metadata()
    settings = Settings()

    _score, top_signals, _finding = analyze_certificate(
        metadata,
        settings,
        domain_burst_counts={"example.com": settings.anomaly_thresholds.domain_burst_count},
    )

    burst_signal = next(signal for signal in top_signals if signal.code == "registered_domain_burst")
    assert burst_signal.severity == "medium"
    assert burst_signal.evidence["matches"][0]["registered_domain"] == "example.com"
