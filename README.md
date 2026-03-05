# ct-analyzer

`ct-analyzer` ingests live Certificate Transparency events from CertStream, filters for GoDaddy and Starfield issuer families, stores certificate metadata plus 30-day observations in ClickHouse, and exposes explainable anomaly and X.509 lint results through a CLI and a minimal JSON API.

## Features

- Async CertStream ingestion with bounded queues and batched ClickHouse writes
- Configurable GoDaddy / Starfield issuer matching by issuer DN, issuer SPKI hash, or hybrid mode
- Deduplicated `certificates` storage with append-only `observations` and `cert_findings`
- Rule-based X.509 lint checks and explainable anomaly scoring with issuer baselines
- Optional `zlint` enrichment for broader X.509 standards/compliance findings
- FastAPI endpoints for issuer summary stats and top anomalies
- Built-in reporting UI for issuer snapshots, grouped breakdowns, and anomaly review
- MCP-compatible tools/resources server for natural-language CT queries from MCP clients
- Docker Compose for ClickHouse and the app container

## Requirements

- Python 3.11+
- Docker / Docker Compose for local ClickHouse

## Quick Start

1. Copy `.env.example` to `.env` and adjust any settings you need.
2. Start ClickHouse and the local CertStream relay:

```bash
docker compose up -d clickhouse certstream
```

3. Install the app locally:

```bash
python -m pip install -e ".[dev]"
```

4. Run migrations:

```bash
python -m ct_analyzer migrate
```

5. Start ingestion:

```bash
python -m ct_analyzer ingest
```

6. Start ingestion in another shell:

```bash
python -m ct_analyzer ingest
```

7. Start the API in another shell:

```bash
python -m ct_analyzer api
```

8. Open the reporting UI:

```text
http://localhost:8000/
```

## CLI

```bash
python -m ct_analyzer migrate
python -m ct_analyzer ingest
python -m ct_analyzer rollup --days 30
python -m ct_analyzer query-issuer-stats --issuer godaddy --days 30
python -m ct_analyzer query-anomalies --issuer godaddy --days 7 --limit 50
python -m ct_analyzer rescore-anomalies --days 30 --limit 50000
python -m ct_analyzer api
python -m ct_analyzer mcp
```

For containerized roles, run them separately:

```bash
docker compose up -d api
docker compose up -d ingest
docker compose up -d rollup
```

## API

- `GET /health`
- `GET /stats/issuer/godaddy?days=30`
- `GET /profile/issuer/godaddy?days=30`
- `GET /reports/issuer/godaddy/stats-range?date_from=2026-03-02&date_to=2026-03-08`
- `GET /reports/issuer/godaddy/profile-range?date_from=2026-03-02&date_to=2026-03-08`
- `GET /reports/issuer/godaddy/daily-counts?date_from=2026-03-02&date_to=2026-03-08`
- `GET /reports/issuer/godaddy/findings-summary?date_from=2026-03-02&date_to=2026-03-08&limit=25`
- `GET /breakdown/issuer/godaddy?group_by=sig_alg&days=30&limit=10`
- `GET /reports/issuer/godaddy/breakdown-range?group_by=sig_alg&date_from=2026-03-02&date_to=2026-03-08&limit=10`
- `GET /anomalies/issuer/godaddy?days=7&limit=50`
- `GET /reports/issuer/godaddy/anomalies-range?date_from=2026-03-02&date_to=2026-03-08&limit=50`
- `GET /certificates/{cert_hash}`
- `GET /certificates/search?...` including bounded `eku_contains`, `finding_code`, and validity-range filtering
- `GET /domains/{registered_domain}/activity?days=7&limit=25`

The same `python -m ct_analyzer api` process also mounts a Streamable HTTP MCP endpoint at `http://localhost:8000/mcp`.

The same process now also serves a browser UI at `GET /`. The UI is read-only and can use a browser session login for human access, while REST and MCP clients continue using bearer API keys.

Available MCP tools:

- `get_issuer_stats(days=30)`
- `get_issuer_stats_range(date_from, date_to)`
- `get_issuer_profile(days=30)`
- `get_issuer_profile_range(date_from, date_to)`
- `get_issuer_daily_counts(date_from, date_to)`
- `get_findings_summary(date_from, date_to, limit=25)`
- `get_issuer_breakdown(group_by="sig_alg", days=30, limit=10)`
- `get_issuer_breakdown_range(group_by="sig_alg", date_from, date_to, limit=10)`
- `get_anomalies(days=7, limit=50)`
- `get_anomalies_range(date_from, date_to, limit=50)`
- `get_certificate(cert_hash)`
- `search_recent_certificates(...)`
- `get_domain_activity(registered_domain, days=7, limit=25)`

`run_rollup` is disabled by default on the MCP surface. Enable it only for trusted admin deployments with `MCP_ENABLE_ADMIN_TOOLS=true`.

Available MCP resources:

- `ct://issuer/godaddy/stats/{days}`
- `ct://issuer/godaddy/profile/{days}`
- `ct://issuer/godaddy/breakdown/{group_by}/{days}/{limit}`
- `ct://issuer/godaddy/anomalies/{days}/{limit}`
- `ct://certificate/{cert_hash}`
- `ct://domain/{registered_domain}/activity/{days}/{limit}`

For desktop-style stdio MCP clients, run:

```bash
python -m ct_analyzer mcp
```

Examples:

- Claude Code HTTP transport:
  `claude mcp add --transport http ct-analyzer http://localhost:8000/mcp`
- Claude Code stdio transport:
  `claude mcp add ct-analyzer python -m ct_analyzer mcp`

For exact Monday-Sunday or arbitrary date-bounded reporting, prefer the `*_range` tools instead of the trailing `days=` tools.

Example anomaly response fields:

- `cert_hash`
- `subject_cn`
- `dns_names`
- `anomaly_score`
- `top_signals`
- `evidence`
- `finding_severity_counts`

Additional investigation endpoints expose bounded raw detail for drill-down and pivoting without exposing arbitrary SQL:

- certificate lookup by `cert_hash`
- recent certificate search with bounded filters and limits
- EKU substring filtering to help agents find unusual or exact dotted OIDs
- direct finding-code filtering so agents can retrieve certificates matching a specific `ZLINT_...` rule or custom finding
- recent activity for one registered domain
- issuer profile/baseline summaries for common GoDaddy certificate attributes
- grouped issuer breakdowns by signature algorithm, key type, EKU set, finding code, anomaly bucket, domain, and other bounded dimensions

Supported breakdown `group_by` values:

- `issuer_cn`
- `issuer_dn`
- `sig_alg`
- `key_type`
- `key_size`
- `eku_set`
- `finding_code`
- `severity`
- `anomaly_bucket`
- `registered_domain`
- `validity_bucket`
- `san_count_bucket`

## Configuration

Key environment variables:

- `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `CLICKHOUSE_DATABASE`
- `WINDOW_DAYS`
- `CERTSTREAM_URL`
- `AUTH_ENABLED`, `API_KEYS`
- `UI_ADMIN_USERNAME`, `UI_ADMIN_PASSWORD`, `SESSION_SECRET_KEY`, `SESSION_COOKIE_NAME`, `SESSION_HTTPS_ONLY`
- `ZLINT_ENABLED`, `ZLINT_BIN_PATH`, `ZLINT_ARGS`, `ZLINT_TIMEOUT_SECONDS`
- `GODADDY_MATCH_MODE`
- `GODADDY_ISSUER_SUBSTRINGS`
- `GODADDY_ISSUER_SPKI_HASHES`
- `INGEST_QUEUE_SIZE`, `INGEST_WORKERS`, `INGEST_BATCH_SIZE`, `INGEST_FLUSH_SECONDS`
- `ROLLUP_INTERVAL_SECONDS`
- `MCP_ALLOWED_HOSTS`, `MCP_ALLOWED_ORIGINS`
- `MCP_ENABLE_ADMIN_TOOLS`
- `ANOMALY_*`

The default `CERTSTREAM_URL` is `ws://localhost:8080/full-stream`, which expects the local `certstream-server-go` container started by Docker Compose. This avoids depending on the unreliable public CaliDog demo feed while preserving the same CertStream-compatible websocket message shape.

For LAN or public MCP testing, add the reachable hostnames or IPs to `MCP_ALLOWED_HOSTS` and `MCP_ALLOWED_ORIGINS`. For example:

```env
MCP_ALLOWED_HOSTS=127.0.0.1:*,localhost:*,[::1]:*,10.0.0.220:*
MCP_ALLOWED_ORIGINS=http://127.0.0.1:*,http://localhost:*,http://[::1]:*,http://10.0.0.220:*
```

For production, enable API auth and configure one or more shared keys:

```env
AUTH_ENABLED=true
API_KEYS=replace-with-a-long-random-key
```

### ClickHouse Log Retention

By default, ClickHouse system log tables can grow quickly (`system.text_log`, `system.trace_log`, `system.query_log`, and `system.processors_profile_log`).

This repo includes `clickhouse/config.d/system-log-retention.xml` and mounts it into the ClickHouse container to bound retention with TTLs.

Apply it by restarting ClickHouse:

```bash
docker compose up -d --force-recreate clickhouse
```

If you already accumulated large system log tables, you can reclaim space:

```bash
docker compose exec clickhouse clickhouse-client --query "TRUNCATE TABLE system.text_log"
docker compose exec clickhouse clickhouse-client --query "TRUNCATE TABLE system.trace_log"
docker compose exec clickhouse clickhouse-client --query "TRUNCATE TABLE system.processors_profile_log"
docker compose exec clickhouse clickhouse-client --query "TRUNCATE TABLE system.query_log"
docker compose exec clickhouse clickhouse-client --query "TRUNCATE TABLE system.part_log"
```

When auth is enabled, send either:

- `Authorization: Bearer <key>`
- `X-API-Key: <key>`

For UI session login, configure a single admin user and session secret:

```env
UI_ADMIN_USERNAME=admin
UI_ADMIN_PASSWORD=replace-with-a-strong-password
SESSION_SECRET_KEY=replace-with-a-long-random-secret
SESSION_COOKIE_NAME=ct_analyzer_session
SESSION_HTTPS_ONLY=true
```

To enable optional `zlint` enrichment during ingest, install a local `zlint` binary on the host or in the container image and configure:

```env
ZLINT_ENABLED=true
ZLINT_BIN_PATH=zlint
ZLINT_ARGS=-format,json
ZLINT_TIMEOUT_SECONDS=10
```

When enabled, matched certificates are run through `zlint` during ingest and any non-pass results are stored as additional `cert_findings` with a `ZLINT_` prefix. The ingest pipeline does not fail if `zlint` is missing or times out; it logs and continues.

The provided Docker image now bakes in a pinned `zlint` binary, so containerized deployments only need to set `ZLINT_ENABLED=true` and rebuild the image.

Issuer matching behavior:

- `issuer_dn`: substring match against `GODADDY_ISSUER_SUBSTRINGS`
- `issuer_spki`: stable match against configured issuer SPKI hashes
- `hybrid`: accept either DN or SPKI matches

## Data Model

### `certificates`

ReplacingMergeTree keyed by `cert_hash`, with `last_seen` used as the version column. This table stores parsed leaf certificate metadata and the current anomaly score.

### `observations`

Append-only MergeTree partitioned by day. Rows are retained for 30 days using a table TTL on `seen_at`.

### `cert_findings`

One row per finding. Lint findings are stored individually and anomaly evidence is stored under the `ANOMALY_SCORE` finding code.

### Rollups

`python -m ct_analyzer rollup --days 30` refreshes:

- `issuer_daily_stats`
- `issuer_sigalg_stats`

These tables make issuer-level stats and spike detection queries cheaper.

## Tests

```bash
pytest
```

The fixture certificates under `tests/fixtures/` cover:

- Stable hashing from DER
- Registered domain extraction and tokenization
- Issuer matching rules
- Lint findings for weak RSA and missing SAN cases
- Entropy heuristic behavior
