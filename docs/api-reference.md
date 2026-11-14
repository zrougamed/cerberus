# API reference

All JSON routes accept `GET` only unless noted. Typical `Accept: application/json` is optional; responses use `application/json` with UTF-8.

Base URL is whatever host/port `CERBERUS_HTTP_ADDR` binds to (default `http://127.0.0.1:8080`).

## REST: `/api/v1`

| Path | Description |
|------|-------------|
| `GET /api/v1/summary` | Fleet snapshot: packet counters, device count, ranked services/vendors/DNS stats, recent devices, encrypted DNS / TLS version aggregates where computed, correlated-domain hints, **and** fields the Control Room overview expects. Implementation aggregates from current in-memory devices. |
| `GET /api/v1/devices` | Array of full per-MAC `DeviceInfo`-compatible objects (JSON-tagged fields only). Includes `is_gateway` (true once the MAC is observed sourcing IPv4 packets with a non-local source IP) and `forwarded_source_count` (number of such forwarded packets). |
| `GET /api/v1/alerts` | Array of recent rule-based `AlertEvent` objects (threshold monitor). |
| `GET /api/v1/anomalies` | Single **anomaly snapshot** object: model status, scores, last features, recent alerts with `summary` (plain) and `detail` (technical), `last_summary` / `last_summary_detail` / `last_contributions`, etc. |
| `GET /api/v1/version` | `{ "commit": "<short-sha>", "date": "<RFC3339>" }` build metadata stamped at compile time via `-ldflags -X`. Both fields are `"unknown"` for builds without git or ldflags. |

Errors: non-GET returns **405** with plain text body `method not allowed`.

## Prometheus

| Path | Description |
|------|-------------|
| `GET /metrics` | Prometheus text exposition format; scrapes monitor packet counters and related gauges/counters. Includes `cerberus_build_info{commit="…",date="…"} 1` for build provenance. |

### Kernel-side counters

The TC classifier keeps its own per-CPU counters (the `counters` map in
`ebpf/cerberus_tc.c`). They count every packet the hook sees, including those
that produce no event, so they can be compared with `cerberus_packets_total`.

| Series | Meaning |
|--------|---------|
| `cerberus_kernel_packets_total{class}` | Packets seen, by class: `total`, `arp`, `ipv4`, `ipv6`, `other` |
| `cerberus_kernel_bytes_total{class}` | Bytes seen, same classes |
| `cerberus_ringbuf_dropped_events_total` | Events lost because the ring buffer was full. If this rises, the monitor is missing traffic: user space is too slow, or someone is flooding the link to blind it. |

If the counters cannot be read, the scrape contains a
`# kernel counters unavailable: …` comment instead of these series.

## Static assets (Control Room)

Served from the embedded `internal/api/web` tree via the default file server on `/`:

| Path | Role |
|------|------|
| `/` or `/index.html` | SPA shell |
| `/app.js` | Routing, fetch, render |
| `/styles.css` | Layout and theme tokens |

There is no separate API prefix for static files; unknown paths fall through to files under `web/`. API paths are reserved under `/api/` and `/metrics`.

## Response headers

Every response sets a strict `Content-Security-Policy` (`default-src 'none'`,
scripts and styles only from the server itself plus Google Fonts, same-origin
API calls, `frame-ancestors 'none'`; no inline script or style is allowed),
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy` and
`Cross-Origin-Opener-Policy: same-origin`. `/api/` responses also set
`Cache-Control: no-store`.

## CORS and auth

The embedded server does **not** configure CORS or authentication. Run behind a reverse proxy if you need those for remote access.

## Related

- [web-ui.md](web-ui.md) — which endpoints each UI route calls.
- [system-overview.md](system-overview.md) — where response data is produced in the monitor.
