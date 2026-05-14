# API reference

All JSON routes accept `GET` only unless noted. Typical `Accept: application/json` is optional; responses use `application/json` with UTF-8.

Base URL is whatever host/port `CERBERUS_HTTP_ADDR` binds to (default `http://127.0.0.1:8080`).

## REST: `/api/v1`

| Path | Description |
|------|-------------|
| `GET /api/v1/summary` | Fleet snapshot: packet counters, device count, ranked services/vendors/DNS stats, recent devices, encrypted DNS / TLS version aggregates where computed, correlated-domain hints, **and** fields the Control Room overview expects. Implementation aggregates from current in-memory devices. |
| `GET /api/v1/devices` | Array of full per-MAC `DeviceInfo`-compatible objects (JSON-tagged fields only). |
| `GET /api/v1/alerts` | Array of recent rule-based `AlertEvent` objects (threshold monitor). |
| `GET /api/v1/anomalies` | Single **anomaly snapshot** object: model status, scores, last features, recent alerts with `summary` (plain) and `detail` (technical), `last_summary` / `last_summary_detail` / `last_contributions`, etc. |
| `GET /api/v1/version` | `{ "commit": "<short-sha>", "date": "<RFC3339>" }` build metadata stamped at compile time via `-ldflags -X`. Both fields are `"unknown"` for builds without git or ldflags. |

Errors: non-GET returns **405** with plain text body `method not allowed`.

## Prometheus

| Path | Description |
|------|-------------|
| `GET /metrics` | Prometheus text exposition format; scrapes monitor packet counters and related gauges/counters. Includes `cerberus_build_info{commit="…",date="…"} 1` for build provenance. |

## Static assets (Control Room)

Served from the embedded `internal/api/web` tree via the default file server on `/`:

| Path | Role |
|------|------|
| `/` or `/index.html` | SPA shell |
| `/app.js` | Routing, fetch, render |
| `/styles.css` | Layout and theme tokens |

There is no separate API prefix for static files; unknown paths fall through to files under `web/`. API paths are reserved under `/api/` and `/metrics`.

## CORS and auth

The embedded server does **not** configure CORS or authentication. Run behind a reverse proxy if you need those for remote access.

## Related

- [web-ui.md](web-ui.md) — which endpoints each UI route calls.
- [system-overview.md](system-overview.md) — where response data is produced in the monitor.
