CREATE DATABASE IF NOT EXISTS ct_analyzer;

CREATE TABLE IF NOT EXISTS ct_analyzer.certificates
(
    cert_hash String,
    subject_cn String,
    subject_dn String,
    issuer_cn String,
    issuer_dn String,
    issuer_spki_hash Nullable(String),
    serial_number String,
    not_before DateTime,
    not_after DateTime,
    dns_names Array(String),
    san_count UInt16,
    has_wildcard UInt8,
    has_punycode UInt8,
    validity_days UInt16,
    key_type LowCardinality(String),
    key_size UInt16,
    sig_alg LowCardinality(String),
    eku Array(String),
    key_usage Array(String),
    basic_constraints_ca UInt8,
    ski Nullable(String),
    aki Nullable(String),
    policy_oids Array(String),
    aia_ocsp_urls Array(String),
    crl_dp_urls Array(String),
    has_must_staple UInt8,
    has_ip_san UInt8,
    has_uri_san UInt8,
    has_email_san UInt8,
    subject_has_non_ascii UInt8,
    issuer_has_non_ascii UInt8,
    subject_dn_length UInt16,
    issuer_dn_length UInt16,
    first_seen DateTime,
    last_seen DateTime,
    anomaly_score UInt8
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (cert_hash);

CREATE TABLE IF NOT EXISTS ct_analyzer.observations
(
    seen_at DateTime,
    cert_hash String,
    registered_domain String,
    issuer_key LowCardinality(String),
    log_id LowCardinality(String),
    source LowCardinality(String) DEFAULT 'certstream',
    domain_tokens Array(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(seen_at)
ORDER BY (registered_domain, seen_at, cert_hash)
TTL seen_at + INTERVAL 30 DAY DELETE;

CREATE TABLE IF NOT EXISTS ct_analyzer.cert_findings
(
    cert_hash String,
    finding_code LowCardinality(String),
    severity LowCardinality(String),
    evidence_json String,
    created_at DateTime
)
ENGINE = MergeTree
ORDER BY (cert_hash, finding_code, created_at);

CREATE TABLE IF NOT EXISTS ct_analyzer.issuer_daily_stats
(
    day Date,
    issuer_key LowCardinality(String),
    cert_count UInt64,
    domain_count UInt64,
    wildcard_count UInt64,
    punycode_count UInt64,
    ip_san_count UInt64,
    uri_san_count UInt64,
    email_san_count UInt64,
    unusual_eku_count UInt64,
    ca_true_leaf_count UInt64,
    updated_at DateTime
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (issuer_key, day);

CREATE TABLE IF NOT EXISTS ct_analyzer.issuer_sigalg_stats
(
    day Date,
    issuer_key LowCardinality(String),
    sig_alg LowCardinality(String),
    count UInt64,
    updated_at DateTime
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (issuer_key, day, sig_alg);
