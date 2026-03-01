from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID, NameOID

from ct_analyzer.cert.domains import has_punycode


EKU_LABELS = {
    ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "ocspSigning",
}


@dataclass(slots=True)
class CertificateMetadata:
    cert_hash: str
    subject_cn: str
    subject_dn: str
    issuer_cn: str
    issuer_dn: str
    issuer_spki_hash: str | None
    serial_number: str
    not_before: datetime
    not_after: datetime
    dns_names: list[str]
    san_count: int
    has_wildcard: int
    has_punycode: int
    validity_days: int
    key_type: str
    key_size: int
    sig_alg: str
    eku: list[str]
    key_usage: list[str]
    basic_constraints_ca: int
    ski: str | None
    aki: str | None
    policy_oids: list[str]
    aia_ocsp_urls: list[str]
    crl_dp_urls: list[str]
    has_must_staple: int
    has_ip_san: int
    has_uri_san: int
    has_email_san: int
    subject_has_non_ascii: int
    issuer_has_non_ascii: int
    subject_dn_length: int
    issuer_dn_length: int
    first_seen: datetime
    last_seen: datetime
    anomaly_score: int = 0

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ObservationRecord:
    seen_at: datetime
    cert_hash: str
    registered_domain: str
    issuer_key: str
    log_id: str
    source: str
    domain_tokens: list[str]

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FindingRecord:
    cert_hash: str
    finding_code: str
    severity: str
    evidence_json: str
    created_at: datetime

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Signal:
    code: str
    severity: str
    score: int
    evidence: dict[str, Any]


def _name_value(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    attributes = name.get_attributes_for_oid(oid)
    return attributes[0].value if attributes else ""


def _string_has_non_ascii(value: str) -> int:
    return int(any(ord(ch) > 127 for ch in value))


def _key_info(cert: x509.Certificate) -> tuple[str, int]:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    return public_key.__class__.__name__, 0


def _sig_alg(cert: x509.Certificate) -> str:
    if cert.signature_hash_algorithm is None:
        return cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    return cert.signature_hash_algorithm.name.upper()


def _extension_or_none(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> x509.Extension[Any] | None:
    try:
        return cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None


def _extract_dns_sans(cert: x509.Certificate) -> tuple[list[str], int, int, int]:
    extension = _extension_or_none(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if extension is None:
        return [], 0, 0, 0
    san = extension.value
    dns_names = list(san.get_values_for_type(x509.DNSName))
    return (
        dns_names,
        len(san.get_values_for_type(x509.IPAddress)),
        len(san.get_values_for_type(x509.UniformResourceIdentifier)),
        len(san.get_values_for_type(x509.RFC822Name)),
    )


def _extract_eku(cert: x509.Certificate) -> list[str]:
    extension = _extension_or_none(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if extension is None:
        return []
    values = []
    for oid in extension.value:
        values.append(EKU_LABELS.get(oid.dotted_string, oid._name or oid.dotted_string))
    return values


def _extract_key_usage(cert: x509.Certificate) -> list[str]:
    extension = _extension_or_none(cert, ExtensionOID.KEY_USAGE)
    if extension is None:
        return []
    usage = extension.value
    mapping = {
        "digital_signature": "digitalSignature",
        "content_commitment": "contentCommitment",
        "key_encipherment": "keyEncipherment",
        "data_encipherment": "dataEncipherment",
        "key_agreement": "keyAgreement",
        "key_cert_sign": "keyCertSign",
        "crl_sign": "cRLSign",
        "encipher_only": "encipherOnly",
        "decipher_only": "decipherOnly",
    }
    values: list[str] = []
    for attr, label in mapping.items():
        try:
            if getattr(usage, attr):
                values.append(label)
        except ValueError:
            continue
    return values


def _extract_ski(cert: x509.Certificate) -> str | None:
    extension = _extension_or_none(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if extension is None:
        return None
    return extension.value.digest.hex()


def _extract_aki(cert: x509.Certificate) -> str | None:
    extension = _extension_or_none(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if extension is None or extension.value.key_identifier is None:
        return None
    return extension.value.key_identifier.hex()


def _extract_certificate_policies(cert: x509.Certificate) -> list[str]:
    extension = _extension_or_none(cert, ExtensionOID.CERTIFICATE_POLICIES)
    if extension is None:
        return []
    return [policy.policy_identifier.dotted_string for policy in extension.value]


def _extract_aia_ocsp_urls(cert: x509.Certificate) -> list[str]:
    extension = _extension_or_none(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    if extension is None:
        return []
    urls: list[str] = []
    for access_description in extension.value:
        if access_description.access_method == AuthorityInformationAccessOID.OCSP:
            location = access_description.access_location.value
            urls.append(location)
    return urls


def _extract_crl_dp_urls(cert: x509.Certificate) -> list[str]:
    extension = _extension_or_none(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    if extension is None:
        return []
    urls: list[str] = []
    for point in extension.value:
        if point.full_name is None:
            continue
        for name in point.full_name:
            urls.append(name.value)
    return urls


def _has_must_staple(cert: x509.Certificate) -> int:
    extension = _extension_or_none(cert, ExtensionOID.TLS_FEATURE)
    if extension is None:
        return 0
    return int(any(feature == x509.TLSFeatureType.status_request for feature in extension.value))


def _basic_constraints_ca(cert: x509.Certificate) -> int:
    extension = _extension_or_none(cert, ExtensionOID.BASIC_CONSTRAINTS)
    return int(extension.value.ca) if extension is not None else 0


def extract_certificate_metadata(
    cert: x509.Certificate,
    cert_hash: str,
    seen_at: datetime,
    issuer_spki_hash: str | None = None,
) -> CertificateMetadata:
    subject_cn = _name_value(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _name_value(cert.issuer, NameOID.COMMON_NAME)
    subject_dn = cert.subject.rfc4514_string()
    issuer_dn = cert.issuer.rfc4514_string()
    dns_names, ip_count, uri_count, email_count = _extract_dns_sans(cert)
    key_type, key_size = _key_info(cert)
    not_before = cert.not_valid_before_utc.astimezone(UTC)
    not_after = cert.not_valid_after_utc.astimezone(UTC)
    return CertificateMetadata(
        cert_hash=cert_hash,
        subject_cn=subject_cn,
        subject_dn=subject_dn,
        issuer_cn=issuer_cn,
        issuer_dn=issuer_dn,
        issuer_spki_hash=issuer_spki_hash,
        serial_number=hex(cert.serial_number),
        not_before=not_before,
        not_after=not_after,
        dns_names=dns_names,
        san_count=len(dns_names),
        has_wildcard=int(any(name.startswith("*.") for name in dns_names)),
        has_punycode=int(any(has_punycode(name) for name in dns_names)),
        validity_days=max((not_after - not_before).days, 0),
        key_type=key_type,
        key_size=key_size,
        sig_alg=_sig_alg(cert),
        eku=_extract_eku(cert),
        key_usage=_extract_key_usage(cert),
        basic_constraints_ca=_basic_constraints_ca(cert),
        ski=_extract_ski(cert),
        aki=_extract_aki(cert),
        policy_oids=_extract_certificate_policies(cert),
        aia_ocsp_urls=_extract_aia_ocsp_urls(cert),
        crl_dp_urls=_extract_crl_dp_urls(cert),
        has_must_staple=_has_must_staple(cert),
        has_ip_san=int(ip_count > 0),
        has_uri_san=int(uri_count > 0),
        has_email_san=int(email_count > 0),
        subject_has_non_ascii=_string_has_non_ascii(subject_dn),
        issuer_has_non_ascii=_string_has_non_ascii(issuer_dn),
        subject_dn_length=len(subject_dn),
        issuer_dn_length=len(issuer_dn),
        first_seen=seen_at,
        last_seen=seen_at,
    )


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
