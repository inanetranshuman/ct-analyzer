from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from ct_analyzer.cert.domains import idn_confusable_evidence, organization_tokens, registered_domain_tokens
from ct_analyzer.cert.x509_features import CertificateMetadata, FindingRecord
from ct_analyzer.config import Settings


SUSPICIOUS_DN_RE = re.compile(r"\s{2,}|(^,)|(,,)|,\s*,")
DEPRECATED_SIG_ALGS = {"MD5", "SHA1"}
BRAND_KEYWORDS = {
    "amazon",
    "apple",
    "bankofamerica",
    "chase",
    "dropbox",
    "facebook",
    "github",
    "google",
    "microsoft",
    "okta",
    "onedrive",
    "outlook",
    "paypal",
    "stripe",
}


def lint_certificate(metadata: CertificateMetadata, settings: Settings) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    created_at = datetime.now(tz=UTC)

    def add(code: str, severity: str, evidence: dict[str, object]) -> None:
        findings.append(
            FindingRecord(
                cert_hash=metadata.cert_hash,
                finding_code=code,
                severity=severity,
                evidence_json=json.dumps(evidence, sort_keys=True),
                created_at=created_at,
            )
        )

    if metadata.san_count == 0:
        add("SAN_MISSING", "high", {"subject_cn": metadata.subject_cn})

    if metadata.subject_cn and metadata.subject_cn not in metadata.dns_names:
        add("CN_NOT_IN_SAN", "info", {"subject_cn": metadata.subject_cn, "dns_names": metadata.dns_names[:5]})

    if metadata.key_type == "RSA" and metadata.key_size < 2048:
        add("RSA_KEY_TOO_SMALL", "high", {"key_size": metadata.key_size})

    if metadata.sig_alg.upper() in DEPRECATED_SIG_ALGS:
        add("DEPRECATED_SIG_ALGORITHM", "high", {"sig_alg": metadata.sig_alg})

    if metadata.validity_days > settings.anomaly_thresholds.high_validity_days:
        add("VALIDITY_TOO_LONG", "high", {"validity_days": metadata.validity_days})
    elif metadata.validity_days > settings.anomaly_thresholds.medium_validity_days:
        add("VALIDITY_LONG", "medium", {"validity_days": metadata.validity_days})

    if metadata.eku and "serverAuth" not in metadata.eku:
        add("EKU_MISSING_SERVER_AUTH", "medium", {"eku": metadata.eku})

    if metadata.basic_constraints_ca:
        add("LEAF_MARKED_CA", "high", {"basic_constraints_ca": metadata.basic_constraints_ca})

    forbidden_key_usages = {"keyCertSign", "cRLSign"}
    present_forbidden = sorted(forbidden_key_usages.intersection(metadata.key_usage))
    if present_forbidden:
        add("LEAF_KEY_USAGE_CA_BITS", "high", {"key_usage": present_forbidden})

    if metadata.subject_has_non_ascii or metadata.issuer_has_non_ascii:
        add(
            "DN_NON_ASCII",
            "low",
            {"subject_has_non_ascii": metadata.subject_has_non_ascii, "issuer_has_non_ascii": metadata.issuer_has_non_ascii},
        )

    if SUSPICIOUS_DN_RE.search(metadata.subject_dn) or SUSPICIOUS_DN_RE.search(metadata.issuer_dn):
        add("DN_SUSPICIOUS_FORMATTING", "medium", {"subject_dn": metadata.subject_dn, "issuer_dn": metadata.issuer_dn})

    if not metadata.aia_ocsp_urls:
        add("AIA_OCSP_MISSING", "info", {})

    if metadata.subject_org:
        org_tokens = set(organization_tokens(metadata.subject_org))
        domain_tokens = {
            token
            for dns_name in metadata.dns_names
            for token in registered_domain_tokens(dns_name)
        }
        brand_matches = sorted(org_tokens.intersection(BRAND_KEYWORDS))
        if brand_matches and not org_tokens.intersection(domain_tokens):
            add(
                "ORG_BRAND_IMPERSONATION",
                "medium" if metadata.validation_type in {"OV", "EV"} else "low",
                {
                    "subject_org": metadata.subject_org,
                    "brand_matches": brand_matches,
                    "domain_tokens": sorted(domain_tokens),
                    "validation_type": metadata.validation_type,
                },
            )
        if org_tokens and domain_tokens and not org_tokens.intersection(domain_tokens):
            add(
                "ORG_DOMAIN_MISMATCH",
                "medium" if metadata.validation_type in {"OV", "EV"} else "low",
                {
                    "subject_org": metadata.subject_org,
                    "org_tokens": sorted(org_tokens),
                    "domain_tokens": sorted(domain_tokens),
                    "validation_type": metadata.validation_type,
                },
            )

    for dns_name in metadata.dns_names[:10]:
        evidence = idn_confusable_evidence(dns_name)
        if evidence is not None:
            add("IDN_CONFUSABLE", "medium", evidence)
            break

    return findings
