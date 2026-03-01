from __future__ import annotations

from pathlib import Path


def load_schema_sql() -> list[str]:
    schema_path = Path(__file__).with_name("schema.sql")
    statements = []
    for statement in schema_path.read_text().split(";"):
        cleaned = statement.strip()
        if cleaned:
            statements.append(cleaned)
    return statements
