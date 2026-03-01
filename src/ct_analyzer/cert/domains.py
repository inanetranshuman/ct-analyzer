from __future__ import annotations

import math
import re
from functools import lru_cache

from publicsuffix2 import PublicSuffixList


DOMAIN_LABEL_RE = re.compile(r"[a-z0-9-]+")


@lru_cache(maxsize=1)
def _psl() -> PublicSuffixList:
    return PublicSuffixList()


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def get_registered_domain(hostname: str) -> str:
    value = normalize_hostname(hostname)
    if not value or value.startswith("*."):
        value = value[2:]
    if not value:
        return ""
    return _psl().get_public_suffix(value) or value


def tokenize_domain(hostname: str) -> list[str]:
    value = normalize_hostname(hostname).lstrip("*.")
    if not value:
        return []
    parts = [part for part in value.split(".") if part]
    tokens: list[str] = []
    for index in range(len(parts)):
        tokens.append(".".join(parts[index:]))
    return tokens


def has_punycode(hostname: str) -> bool:
    return "xn--" in normalize_hostname(hostname)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [value.count(ch) / len(value) for ch in set(value)]
    return -sum(prob * math.log2(prob) for prob in probabilities)


def highest_label_entropy(hostname: str) -> float:
    labels = [label for label in normalize_hostname(hostname).split(".") if DOMAIN_LABEL_RE.fullmatch(label)]
    if not labels:
        return 0.0
    return max(shannon_entropy(label) for label in labels)


def contains_suspicious_keyword(hostname: str, keywords: list[str]) -> list[str]:
    lowered = normalize_hostname(hostname)
    return [keyword for keyword in keywords if keyword.lower() in lowered]
