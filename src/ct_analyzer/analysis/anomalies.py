from __future__ import annotations

import json
from datetime import UTC, datetime

from ct_analyzer.analysis.baseline import IssuerBaseline
from ct_analyzer.analysis.scoring import score_signals
from ct_analyzer.cert.domains import (
    contains_suspicious_keyword,
    has_punycode,
    highest_label_entropy,
    idn_confusable_evidence,
    organization_tokens,
    registered_domain_tokens,
    to_unicode_hostname,
)
from ct_analyzer.cert.x509_features import CertificateMetadata, FindingRecord, Signal
from ct_analyzer.config import Settings


def analyze_certificate(
    metadata: CertificateMetadata,
    settings: Settings,
    baseline: IssuerBaseline | None = None,
    domain_burst_counts: dict[str, int] | None = None,
) -> tuple[int, list[Signal], FindingRecord]:
    signals: list[Signal] = []
    thresholds = settings.anomaly_thresholds
    weights = settings.anomaly_weights

    if metadata.san_count >= thresholds.high_san_count:
        signals.append(
            Signal(
                code="high_san_count",
                severity="medium",
                score=weights.high_san,
                evidence={"san_count": metadata.san_count, "threshold": thresholds.high_san_count},
            )
        )

    if metadata.has_wildcard:
        severity = "medium" if (baseline and baseline.wildcard_rate < thresholds.wildcard_baseline_rate) else "info"
        signals.append(
            Signal(code="wildcard_san", severity=severity, score=weights.wildcard, evidence={"dns_names": metadata.dns_names[:5]})
        )

    if metadata.subject_org:
        org_tokens = set(organization_tokens(metadata.subject_org))
        domain_tokens = {
            token
            for dns_name in metadata.dns_names
            for token in registered_domain_tokens(dns_name)
        }
        if org_tokens and domain_tokens and not org_tokens.intersection(domain_tokens):
            signals.append(
                Signal(
                    code="org_domain_mismatch",
                    severity="medium" if metadata.validation_type in {"OV", "EV"} else "info",
                    score=weights.org_domain_mismatch,
                    evidence={
                        "subject_org": metadata.subject_org,
                        "org_tokens": sorted(org_tokens),
                        "domain_tokens": sorted(domain_tokens),
                        "validation_type": metadata.validation_type,
                    },
                )
            )
        brand_keywords = {
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
        brand_matches = sorted(org_tokens.intersection(brand_keywords))
        if brand_matches and not org_tokens.intersection(domain_tokens):
            signals.append(
                Signal(
                    code="brand_org_impersonation",
                    severity="high" if metadata.validation_type in {"OV", "EV"} else "medium",
                    score=weights.brand_org_impersonation,
                    evidence={
                        "subject_org": metadata.subject_org,
                        "brand_matches": brand_matches,
                        "domain_tokens": sorted(domain_tokens),
                        "validation_type": metadata.validation_type,
                    },
                )
            )

    domain_burst_matches = []
    if domain_burst_counts:
        for registered_domain, cert_count in sorted(domain_burst_counts.items(), key=lambda item: item[1], reverse=True):
            if cert_count >= thresholds.domain_burst_count:
                domain_burst_matches.append({"registered_domain": registered_domain, "cert_count": cert_count})
    if domain_burst_matches:
        highest_burst = domain_burst_matches[0]["cert_count"]
        severity = "high" if highest_burst >= thresholds.domain_burst_count * 2 else "medium"
        signals.append(
            Signal(
                code="registered_domain_burst",
                severity=severity,
                score=weights.domain_burst,
                evidence={
                    "matches": domain_burst_matches[:5],
                    "threshold": thresholds.domain_burst_count,
                    "window_hours": thresholds.domain_burst_window_hours,
                },
            )
        )

    confusable_by_san: dict[str, dict[str, object]] = {}
    confusable_matches = []
    for san in metadata.dns_names[:10]:
        evidence = idn_confusable_evidence(san)
        if evidence is not None:
            confusable_by_san[san] = evidence
            confusable_matches.append(evidence)

    entropy_matches = []
    punycode_entropy_matches = []
    for san in metadata.dns_names:
        punycode_label = has_punycode(san)
        if punycode_label and san not in confusable_by_san:
            continue
        entropy_input = to_unicode_hostname(san) if punycode_label else san
        entropy = highest_label_entropy(entropy_input)
        if entropy >= thresholds.high_entropy_threshold:
            match = {"san": san, "entropy": round(entropy, 3)}
            entropy_matches.append(match)
            if punycode_label:
                punycode_entropy_matches.append(match)
    if entropy_matches:
        signals.append(
            Signal(
                code="high_entropy_label",
                severity="medium",
                score=weights.entropy,
                evidence={"matches": entropy_matches[:5], "threshold": thresholds.high_entropy_threshold},
            )
        )

    if confusable_matches:
        signals.append(
            Signal(
                code="idn_confusable",
                severity="medium",
                score=weights.idn_confusable,
                evidence={"matches": confusable_matches[:5]},
            )
        )

    if metadata.has_punycode:
        # Punycode alone is common for legitimate IDNs, so keep the standalone signal weak.
        standalone_score = max(2, weights.punycode // 4)
        severity = "info"
        if baseline and baseline.punycode_rate < thresholds.punycode_baseline_rate:
            severity = "low"
        signals.append(
            Signal(
                code="punycode_san",
                severity=severity,
                score=standalone_score,
                evidence={"dns_names": metadata.dns_names[:5]},
            )
        )
        if punycode_entropy_matches:
            signals.append(
                Signal(
                    code="punycode_entropy_combo",
                    severity="medium",
                    score=max(weights.punycode, weights.entropy),
                    evidence={
                        "dns_names": metadata.dns_names[:5],
                        "matches": punycode_entropy_matches[:5],
                        "threshold": thresholds.high_entropy_threshold,
                    },
                )
            )

    keywords = sorted({kw for san in metadata.dns_names for kw in contains_suspicious_keyword(san, thresholds.suspicious_keywords)})
    if keywords:
        signals.append(
            Signal(code="suspicious_keywords", severity="info", score=weights.keyword, evidence={"keywords": keywords})
        )

    if baseline and baseline.validity_p95 and metadata.validity_days > baseline.validity_p95:
        signals.append(
            Signal(
                code="validity_outlier",
                severity="medium",
                score=weights.validity,
                evidence={"validity_days": metadata.validity_days, "baseline_p95": baseline.validity_p95},
            )
        )
    elif metadata.validity_days > thresholds.medium_validity_days:
        signals.append(
            Signal(
                code="validity_long",
                severity="medium",
                score=weights.validity,
                evidence={"validity_days": metadata.validity_days},
            )
        )

    extension_evidence = {}
    if metadata.has_ip_san:
        extension_evidence["has_ip_san"] = True
    if metadata.has_uri_san:
        extension_evidence["has_uri_san"] = True
    if metadata.has_email_san:
        extension_evidence["has_email_san"] = True
    if extension_evidence:
        signals.append(
            Signal(code="rare_san_types", severity="medium", score=weights.extension, evidence=extension_evidence)
        )

    if baseline and metadata.eku:
        eku_key = ",".join(sorted(metadata.eku))
        if baseline.common_eku_sets and eku_key not in baseline.common_eku_sets:
            signals.append(
                Signal(code="unusual_eku_set", severity="medium", score=weights.eku, evidence={"eku": metadata.eku})
            )

    if baseline and baseline.trailing_daily_avg and baseline.current_day_count > baseline.trailing_daily_avg * thresholds.spike_multiplier:
        signals.append(
            Signal(
                code="issuer_spike",
                severity="high",
                score=weights.spike,
                evidence={
                    "current_day_count": baseline.current_day_count,
                    "trailing_daily_avg": round(baseline.trailing_daily_avg, 2),
                },
            )
        )

    score, top_signals = score_signals(signals)
    metadata.anomaly_score = score
    finding = FindingRecord(
        cert_hash=metadata.cert_hash,
        finding_code="ANOMALY_SCORE",
        severity="info",
        evidence_json=json.dumps(
            {
                "anomaly_score": score,
                "top_signals": [
                    {
                        "code": signal.code,
                        "severity": signal.severity,
                        "score": signal.score,
                        "evidence": signal.evidence,
                    }
                    for signal in top_signals
                ],
            },
            sort_keys=True,
        ),
        created_at=datetime.now(tz=UTC),
    )
    return score, top_signals, finding
