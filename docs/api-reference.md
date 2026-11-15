# API reference

All JSON routes accept `GET` only unless noted. Typical `Accept: application/json` is optional; responses use `application/json` with UTF-8.

Base URL is whatever host/port `CERBERUS_HTTP_ADDR` binds to (default `http://127.0.0.1:8080`).

## REST: `/api/v1`

| Path | Description |
|------|-------------|
| `GET /api/v1/summary` | Fleet snapshot: packet counters, device count, ranked services/vendors/DNS stats, recent devices, encrypted DNS / TLS version aggregates where computed, correlated-domain hints, **and** fields the Control Room overview expects. Implementation aggregates from current in-memory devices. |
| `GET /api/v1/devices` | Array of full per-MAC `DeviceInfo`-compatible objects (JSON-tagged fields only). Includes `is_gateway` (true once the MAC is observed sourcing IPv4 packets with a non-local source IP) and `forwarded_source_count` (number of such forwarded packets). |
| `GET /api/v1/alerts` | Array of recent rule-based `AlertEvent` objects (threshold monitor). Each has an `id`; acknowledged ones also carry `acked_by`, `acked_at` and `note`. |
| `POST /api/v1/alerts/{id}/ack` | Analyst. Body `{"note": "..."}` (optional, up to 500 characters). Returns the alert. 404 when the alert has aged out of the history. |
| `GET /api/v1/session` | Who the caller is and how to sign in; see [access-control.md](access-control.md). |
| `GET /api/v1/anomalies` | Single **anomaly snapshot** object: model status, scores, last features, recent alerts with `summary` (plain) and `detail` (technical), `last_summary` / `last_summary_detail` / `last_contributions`, etc. |
| `GET /api/v1/assets` | Industrial asset inventory. Each entry: `mac`, `ip`, `oui_vendor`, `role`, `role_source` (`inferred`, `override` or empty), `protocols`, `asset` (reported identity), `last_seen`. Filters: `?role=`, `?protocol=`; `?format=csv` returns a CSV download with formula-like cells prefixed by `'`. |
| `PUT /api/v1/assets/{mac}/role` | Analyst. Body `{"role": "scada_server"}`; one of `controller`, `hmi`, `scada_server`, `engineering_workstation`, `gateway`, `historian`, `other`, or `""` to go back to the inferred role. Stored with the device immediately. Works without the policy engine. |
| `GET /api/v1/baseline` | Industrial flow baseline: `status` (`state` learning/enforcing/disabled, `started_at`, `learning_until`, counts, `dropped`, `max_flows`) and `flows` (`id`, `client`, `server`, `protocol`, `class`, `status`, `first_seen`, `last_seen`, `count`). `?status=` filters, `?limit=` caps the list (default 500, max 5000). |
| `POST /api/v1/baseline/approve`, `/forget` | Analyst. Body `{"ids": ["<16 hex>", ...]}` (1 to 1000). Approve marks new flows approved; forget removes flows so they alert again. 409 when the baseline is disabled. |
| `POST /api/v1/baseline/relearn` | Admin. Drops all flows and starts a new learning period. |
| `GET /api/v1/zones` | Segmentation: `zones` (id, name, level, cidrs, industrial, enforce, devices), `conduits` (from, to, ports, bidirectional) and `violations` (`"from>to"` -> packets with no conduit). Empty `zones` when none are configured. |
| `GET /api/v1/alerts` techniques | Each alert has `techniques`: ATT&CK for ICS `{id, name}` pairs for its rule, omitted when none apply. See [attack-mapping.md](attack-mapping.md). |
| `GET /api/v1/captures`, `GET/DELETE /api/v1/captures/{id}`, `POST /api/v1/captures` | Packet captures; see [packet-capture.md](packet-capture.md). Download, delete and capture-now need the admin role. |
| `GET /api/v1/segmentation` | Active zones, conduits and zone alert rules, with `source` (`config` or `saved`). |
| `PUT /api/v1/segmentation` | Admin. Replace the whole segmentation; validated like the alerts file, applied without a restart, saved across restarts. 400 returns the reason. |
| `DELETE /api/v1/segmentation` | Admin. Discard saved changes and use the alerts file again. |
| `GET /api/v1/advisories` | Advisory bundle status: `loaded`, `path`, `generated_at`, `source`, `advisories`, `age_days`, `stale`, `error`. |
| `POST /api/v1/advisories/reload` | Admin. Re-read the bundle file. |
| `GET /api/v1/assets/{mac}/advisories` | Matching advisories for one device, highest score first, each with `confidence`. Asset entries also carry `advisories` (count) and `advisory_severity`. See [advisories.md](advisories.md). |
| `GET /api/v1/version` | `{ "commit": "<short-sha>", "date": "<RFC3339>" }` build metadata stamped at compile time via `-ldflags -X`. Both fields are `"unknown"` for builds without git or ldflags. |

Errors: non-GET returns **405** with plain text body `method not allowed`.

## Policy

Active response; see [active-response.md](active-response.md). Writes need the
admin role: `Authorization: Bearer $CERBERUS_API_TOKEN`, an admin named token,
or an admin browser session (see [access-control.md](access-control.md)).
With no way to authenticate configured they return **403**. Ten failed attempts per client per minute return
**429**. Bodies are JSON, at most 16 KiB, unknown fields rejected. Errors are
`{"error": "..."}`.

| Method and path | Body | Success |
|-----------------|------|---------|
| `GET /api/v1/policy` | | **200** `{mode, kernel_attached, max_rules, max_filters, writes_enabled, filters: [{id, position, summary, enabled, match, verdict, log, counters, ...}], rules: [{id, action, mac \| cidr, direction, comment, created_at, created_by, expires_at, counters: {packets, bytes}}], audit: [{at, actor, action, rule_id, detail}]}` |
| `PUT /api/v1/policy/mode` | `{"mode": "monitor" \| "enforce"}` | **200** `{"mode": ...}` |
| `POST /api/v1/policy/rules` | `{id?, action: "drop" \| "log", mac? \| cidr? \| hostname?, host_match?: "dns" \| "sni" \| "any", direction?: "src" \| "dst" \| "any", comment?, ttl_seconds?, force?}` | **201** the rule. Hostname rules match observed DNS / TLS SNI (wildcard `*.evil.com` allowed) and auto-quarantine matching device MACs. Interactive OpenAPI UI: `/docs` (`/openapi.yaml`). |
| `DELETE /api/v1/policy/rules/{id}` | | **204** |
| `POST /api/v1/policy/filters` | `{id?, verdict: "accept" \| "drop" \| "continue", match: {interface?, family?, protocol?, src?, src_not?, dst?, dst_not?, src_mac?, src_port?, src_port_not?, dst_port?, dst_port_not?, tcp_flags_any?, tcp_flags_all?, icmp_type?, icmp_code?}, log?, log_every_seconds?, comment?, ttl_seconds?, position?, disabled?, force?}` | **201** the rule |
| `DELETE /api/v1/policy/filters/{id}` | | **204** |
| `PUT /api/v1/policy/filters/{id}/position` | `{"position": n}` (0-based) | **204** |
| `PUT /api/v1/policy/filters/{id}/enabled` | `{"enabled": true \| false}` | **204** |
| `GET /api/v1/policy/log?limit=N` | | **200** newest log entries (1-500, default 100) |

Errors: **400** invalid input, **401** bad token, **403** role too low, **404** unknown rule,
**409** duplicate id/address or policy full, **422** covers a protected
address (resend with `"force": true`), **500** kernel or storage failure (the
change was rolled back). The optional `X-Cerberus-Actor` header labels the
change in the audit trail when the shared `CERBERUS_API_TOKEN` is used;
named tokens and signed-in users are recorded under their own name.

## Prometheus

| Path | Description |
|------|-------------|
| `GET /metrics` | Prometheus text exposition format; scrapes monitor packet counters and related gauges/counters. Includes `cerberus_build_info{commit="…",date="…"} 1` for build provenance. |

`cerberus_zone_violations_total{from,to}` counts packets between zones that no conduit allows.

`cerberus_baseline_flows{status}`, `cerberus_baseline_dropped_total` and `cerberus_baseline_learning` describe the flow baseline (omitted when it is disabled).

`cerberus_industrial_messages_total{protocol,class,direction}` counts decoded
industrial messages (see [industrial-protocols.md](industrial-protocols.md)).
The series appear once the first message is decoded.

### Kernel-side counters

The TC classifier keeps its own per-CPU counters (the `counters` map in
`ebpf/cerberus_tc.c`). They count every packet the hook sees, including those
that produce no event, so they can be compared with `cerberus_packets_total`.

| Series | Meaning |
|--------|---------|
| `cerberus_kernel_packets_total{class}` | Packets seen, by class: `total`, `arp`, `ipv4`, `ipv6`, `other` |
| `cerberus_kernel_bytes_total{class}` | Bytes seen, same classes |
| `cerberus_policy_dropped_packets_total` | Packets dropped by enforced policy rules |
| `cerberus_filter_log_lost_total` | Filter log entries lost to a full log buffer |
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

The embedded server does not configure CORS. Read endpoints are open unless
`protect_reads` is set in the auth file; changes need a role. Roles, named
tokens and OIDC sign-in are described in [access-control.md](access-control.md).
Serve Cerberus over HTTPS (a reverse proxy works) before using sign-in or
tokens across a network.

## Related

- [web-ui.md](web-ui.md) — which endpoints each UI route calls.
- [system-overview.md](system-overview.md) — where response data is produced in the monitor.
