from __future__ import annotations

import json

from ct_analyzer.analysis.zlint import _normalize_code, _extract_result_fields


def test_zlint_code_normalization() -> None:
    assert _normalize_code("e_subject_common_name_not_from_san") == "ZLINT_E_SUBJECT_COMMON_NAME_NOT_FROM_SAN"


def test_extract_result_fields_from_result_object() -> None:
    status, details, source = _extract_result_fields(
        {"result": "warn", "details": "example", "source": "RFC 5280"}
    )
    assert status == "warn"
    assert details == "example"
    assert source == "RFC 5280"
