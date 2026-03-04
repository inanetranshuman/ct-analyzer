from __future__ import annotations

import math
import re
import unicodedata
from functools import lru_cache

from publicsuffix2 import PublicSuffixList


DOMAIN_LABEL_RE = re.compile(r"[a-z0-9-]+")
COMBINING_MARK_RE = re.compile(r"[\u0300-\u036f]")
ASCII_ALNUM_RE = re.compile(r"[a-z0-9]")
ORG_TOKEN_RE = re.compile(r"[a-z0-9]+")

ORG_STOPWORDS = {
    "and",
    "co",
    "company",
    "corp",
    "corporation",
    "gmbh",
    "group",
    "holdings",
    "inc",
    "incorporated",
    "limited",
    "llc",
    "ltd",
    "of",
    "plc",
    "pte",
    "sa",
    "services",
    "solutions",
    "systems",
    "the",
}

CONFUSABLE_CHAR_MAP = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
    "ԛ": "q",
    "գ": "g",
    "α": "a",
    "β": "b",
    "γ": "y",
    "δ": "d",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "ø": "o",
    "ö": "o",
    "ó": "o",
    "ò": "o",
    "ô": "o",
    "õ": "o",
    "ä": "a",
    "á": "a",
    "à": "a",
    "â": "a",
    "ã": "a",
    "å": "a",
    "ë": "e",
    "é": "e",
    "è": "e",
    "ê": "e",
    "ï": "i",
    "í": "i",
    "ì": "i",
    "î": "i",
    "ü": "u",
    "ú": "u",
    "ù": "u",
    "û": "u",
    "ñ": "n",
    "ç": "c",
}


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


def to_unicode_hostname(hostname: str) -> str:
    value = normalize_hostname(hostname)
    if not value:
        return ""
    wildcard = value.startswith("*.")
    if wildcard:
        value = value[2:]
    try:
        decoded = value.encode("ascii").decode("idna")
    except UnicodeError:
        decoded = value
    return f"*.{decoded}" if wildcard else decoded


def organization_tokens(value: str) -> list[str]:
    if not value:
        return []
    normalized = unicodedata.normalize("NFKD", value.lower())
    without_marks = COMBINING_MARK_RE.sub("", normalized)
    tokens = ORG_TOKEN_RE.findall(without_marks)
    return [token for token in tokens if len(token) > 2 and token not in ORG_STOPWORDS]


def registered_domain_tokens(hostname: str) -> list[str]:
    registered = get_registered_domain(hostname)
    if not registered:
        return []
    tokens: list[str] = []
    for label in registered.split("."):
        tokens.extend(organization_tokens(label))
    return tokens


def _label_script(char: str) -> str | None:
    if char.isascii():
        if char.isalpha():
            return "latin"
        if char.isdigit():
            return "digit"
        return None
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "other"
    if "LATIN" in name:
        return "latin"
    if "CYRILLIC" in name:
        return "cyrillic"
    if "GREEK" in name:
        return "greek"
    return "other"


def confusable_skeleton(value: str) -> str:
    lowered = value.lower()
    normalized = unicodedata.normalize("NFKD", lowered)
    without_marks = COMBINING_MARK_RE.sub("", normalized)
    return "".join(CONFUSABLE_CHAR_MAP.get(char, char) for char in without_marks)


def idn_confusable_evidence(hostname: str) -> dict[str, object] | None:
    unicode_hostname = to_unicode_hostname(hostname)
    if not unicode_hostname or unicode_hostname == normalize_hostname(hostname):
        return None

    labels = [label for label in unicode_hostname.lstrip("*.").split(".") if label]
    matches: list[dict[str, object]] = []
    for label in labels:
        if label.isascii():
            continue
        scripts = {
            script
            for char in label
            if (script := _label_script(char)) not in {None, "digit"}
        }
        skeleton = confusable_skeleton(label)
        mixed_script = len(scripts) > 1
        ascii_blend = bool(ASCII_ALNUM_RE.search(label)) and any(ord(char) > 127 for char in label)
        ascii_lookalike = skeleton.isascii() and skeleton != label.lower()
        if mixed_script or ascii_blend or ascii_lookalike:
            matches.append(
                {
                    "label": label,
                    "skeleton": skeleton,
                    "scripts": sorted(scripts),
                    "mixed_script": mixed_script,
                }
            )

    if not matches:
        return None
    return {
        "hostname": normalize_hostname(hostname),
        "unicode_hostname": unicode_hostname,
        "matches": matches,
    }


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
