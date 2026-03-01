from __future__ import annotations

from ct_analyzer.cert.x509_features import Signal


def score_signals(signals: list[Signal]) -> tuple[int, list[Signal]]:
    ranked = sorted(signals, key=lambda signal: signal.score, reverse=True)
    return min(sum(signal.score for signal in ranked), 100), ranked[:3]
