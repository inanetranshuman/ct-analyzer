from __future__ import annotations

import json
from datetime import UTC, datetime

from ct_analyzer.analysis.baseline import IssuerBaseline
from ct_analyzer.analysis.scoring import score_signals
from ct_analyzer.cert.domains import contains_suspicious_keyword, highest_label_entropy
from ct_analyzer.cert.x509_features import CertificateMetadata, FindingRecord, Signal
from ct_analyzer.config import Settings


def analyze_certificate(
    metadata: CertificateMetadata,
    settings: Settings,
    baseline: IssuerBaseline | None = None,
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

    if metadata.has_punycode:
        severity = "medium" if (baseline and baseline.punycode_rate < thresholds.punycode_baseline_rate) else "info"
        signals.append(
            Signal(code="punycode_san", severity=severity, score=weights.punycode, evidence={"dns_names": metadata.dns_names[:5]})
        )

    entropy_matches = []
    for san in metadata.dns_names:
        entropy = highest_label_entropy(san)
        if entropy >= thresholds.high_entropy_threshold:
            entropy_matches.append({"san": san, "entropy": round(entropy, 3)})
    if entropy_matches:
        signals.append(
            Signal(
                code="high_entropy_label",
                severity="medium",
                score=weights.entropy,
                evidence={"matches": entropy_matches[:5], "threshold": thresholds.high_entropy_threshold},
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
