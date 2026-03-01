from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, default))


def _env_float(name: str, default: float) -> float:
    return float(os.getenv(name, default))


class ClickHouseSettings(BaseModel):
    host: str = "localhost"
    port: int = 8123
    user: str = "default"
    password: str = ""
    database: str = "ct_analyzer"


class IngestSettings(BaseModel):
    certstream_url: str = "ws://localhost:8080/full-stream"
    queue_size: int = 5000
    workers: int = 4
    batch_size: int = 1000
    flush_seconds: float = 2.0


class ApiSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class MCPSettings(BaseModel):
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    )
    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    )
    enable_admin_tools: bool = False


class AuthSettings(BaseModel):
    enabled: bool = False
    api_keys: list[str] = Field(default_factory=list)


class AnomalyThresholds(BaseModel):
    high_san_count: int = 25
    high_entropy_threshold: float = 3.6
    medium_validity_days: int = 397
    high_validity_days: int = 825
    wildcard_baseline_rate: float = 0.15
    punycode_baseline_rate: float = 0.02
    suspicious_keywords: list[str] = Field(
        default_factory=lambda: ["login", "secure", "account", "sso", "billing"]
    )
    spike_multiplier: float = 2.5


class AnomalyWeights(BaseModel):
    high_san: int = 20
    wildcard: int = 8
    punycode: int = 15
    entropy: int = 18
    keyword: int = 6
    validity: int = 12
    extension: int = 10
    eku: int = 8
    spike: int = 18


class IssuerMatchingSettings(BaseModel):
    match_mode: Literal["issuer_dn", "issuer_spki", "hybrid"] = "hybrid"
    issuer_substrings: list[str] = Field(
        default_factory=lambda: ["Go Daddy", "GoDaddy.com", "Starfield"]
    )
    issuer_spki_hashes: list[str] = Field(default_factory=list)


class Settings(BaseModel):
    log_level: str = "INFO"
    window_days: int = 30
    clickhouse: ClickHouseSettings = Field(default_factory=ClickHouseSettings)
    ingest: IngestSettings = Field(default_factory=IngestSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    mcp: MCPSettings = Field(default_factory=MCPSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    matching: IssuerMatchingSettings = Field(default_factory=IssuerMatchingSettings)
    anomaly_thresholds: AnomalyThresholds = Field(default_factory=AnomalyThresholds)
    anomaly_weights: AnomalyWeights = Field(default_factory=AnomalyWeights)

    @classmethod
    def load(cls) -> "Settings":
        load_dotenv()
        return cls(
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            window_days=_env_int("WINDOW_DAYS", 30),
            clickhouse=ClickHouseSettings(
                host=os.getenv("CLICKHOUSE_HOST", "localhost"),
                port=_env_int("CLICKHOUSE_PORT", 8123),
                user=os.getenv("CLICKHOUSE_USER", "default"),
                password=os.getenv("CLICKHOUSE_PASSWORD", ""),
                database=os.getenv("CLICKHOUSE_DATABASE", "ct_analyzer"),
            ),
            ingest=IngestSettings(
                certstream_url=os.getenv(
                    "CERTSTREAM_URL", "ws://localhost:8080/full-stream"
                ),
                queue_size=_env_int("INGEST_QUEUE_SIZE", 5000),
                workers=_env_int("INGEST_WORKERS", 4),
                batch_size=_env_int("INGEST_BATCH_SIZE", 1000),
                flush_seconds=_env_float("INGEST_FLUSH_SECONDS", 2.0),
            ),
            api=ApiSettings(
                host=os.getenv("API_HOST", "0.0.0.0"),
                port=_env_int("API_PORT", 8000),
            ),
            mcp=MCPSettings(
                allowed_hosts=_split_csv(
                    os.getenv(
                        "MCP_ALLOWED_HOSTS",
                        "127.0.0.1:*,localhost:*,[::1]:*",
                    )
                ),
                allowed_origins=_split_csv(
                    os.getenv(
                        "MCP_ALLOWED_ORIGINS",
                        "http://127.0.0.1:*,http://localhost:*,http://[::1]:*",
                    )
                ),
                enable_admin_tools=os.getenv("MCP_ENABLE_ADMIN_TOOLS", "false").lower()
                in {"1", "true", "yes", "on"},
            ),
            auth=AuthSettings(
                enabled=os.getenv("AUTH_ENABLED", "false").lower() in {"1", "true", "yes", "on"},
                api_keys=_split_csv(os.getenv("API_KEYS", "")),
            ),
            matching=IssuerMatchingSettings(
                match_mode=os.getenv("GODADDY_MATCH_MODE", "hybrid"),
                issuer_substrings=_split_csv(
                    os.getenv("GODADDY_ISSUER_SUBSTRINGS", "Go Daddy,GoDaddy.com,Starfield")
                ),
                issuer_spki_hashes=_split_csv(os.getenv("GODADDY_ISSUER_SPKI_HASHES", "")),
            ),
            anomaly_thresholds=AnomalyThresholds(
                high_san_count=_env_int("ANOMALY_HIGH_SAN_COUNT", 25),
                high_entropy_threshold=_env_float("ANOMALY_HIGH_ENTROPY_THRESHOLD", 3.6),
                medium_validity_days=_env_int("ANOMALY_VALIDITY_MEDIUM_DAYS", 397),
                high_validity_days=_env_int("ANOMALY_VALIDITY_HIGH_DAYS", 825),
                wildcard_baseline_rate=_env_float("ANOMALY_WILDCARD_BASELINE_RATE", 0.15),
                punycode_baseline_rate=_env_float("ANOMALY_PUNYCODE_BASELINE_RATE", 0.02),
                suspicious_keywords=_split_csv(
                    os.getenv(
                        "ANOMALY_SUSPICIOUS_KEYWORDS", "login,secure,account,sso,billing"
                    )
                ),
                spike_multiplier=_env_float("ANOMALY_SPIKE_MULTIPLIER", 2.5),
            ),
            anomaly_weights=AnomalyWeights(
                high_san=_env_int("ANOMALY_WEIGHT_HIGH_SAN", 20),
                wildcard=_env_int("ANOMALY_WEIGHT_WILDCARD", 8),
                punycode=_env_int("ANOMALY_WEIGHT_PUNYCODE", 15),
                entropy=_env_int("ANOMALY_WEIGHT_ENTROPY", 18),
                keyword=_env_int("ANOMALY_WEIGHT_KEYWORD", 6),
                validity=_env_int("ANOMALY_WEIGHT_VALIDITY", 12),
                extension=_env_int("ANOMALY_WEIGHT_EXTENSION", 10),
                eku=_env_int("ANOMALY_WEIGHT_EKU", 8),
                spike=_env_int("ANOMALY_WEIGHT_SPIKE", 18),
            ),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.load()
