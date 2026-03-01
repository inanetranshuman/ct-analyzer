# ct-analyzer

`ct-analyzer` ingests live Certificate Transparency events from CertStream, filters for GoDaddy and Starfield issuer families, stores certificate metadata plus 30-day observations in ClickHouse, and exposes explainable anomaly and X.509 lint results through a CLI and a minimal JSON API.

## Features

- Async CertStream ingestion with bounded queues and batched ClickHouse writes
- Configurable GoDaddy / Starfield issuer matching by issuer DN, issuer SPKI hash, or hybrid mode
- Deduplicated `certificates` storage with append-only `observations` and `cert_findings`
- Rule-based X.509 lint checks and explainable anomaly scoring with issuer baselines
- FastAPI endpoints for issuer summary stats and top anomalies
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

## CLI

```bash
python -m ct_analyzer migrate
python -m ct_analyzer ingest
python -m ct_analyzer rollup --days 30
python -m ct_analyzer query-issuer-stats --issuer godaddy --days 30
python -m ct_analyzer query-anomalies --issuer godaddy --days 7 --limit 50
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
- `GET /anomalies/issuer/godaddy?days=7&limit=50`
- `GET /certificates/{cert_hash}`
- `GET /certificates/search?...`
- `GET /domains/{registered_domain}/activity?days=7&limit=25`

The same `python -m ct_analyzer api` process also mounts a Streamable HTTP MCP endpoint at `http://localhost:8000/mcp`.

Available MCP tools:

- `get_issuer_stats(days=30)`
- `get_issuer_profile(days=30)`
- `get_anomalies(days=7, limit=50)`
- `get_certificate(cert_hash)`
- `search_recent_certificates(...)`
- `get_domain_activity(registered_domain, days=7, limit=25)`

`run_rollup` is disabled by default on the MCP surface. Enable it only for trusted admin deployments with `MCP_ENABLE_ADMIN_TOOLS=true`.

Available MCP resources:

- `ct://issuer/godaddy/stats/{days}`
- `ct://issuer/godaddy/profile/{days}`
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
- recent activity for one registered domain
- issuer profile/baseline summaries for common GoDaddy certificate attributes

## Configuration

Key environment variables:

- `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `CLICKHOUSE_DATABASE`
- `WINDOW_DAYS`
- `CERTSTREAM_URL`
- `AUTH_ENABLED`, `API_KEYS`
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

When auth is enabled, send either:

- `Authorization: Bearer <key>`
- `X-API-Key: <key>`

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
