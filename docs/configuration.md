# Configuration (environment)

Cerberus reads the following environment variables at runtime.

| Variable | Default | Effect |
|----------|---------|--------|
| `CERBERUS_HTTP_ADDR` | `127.0.0.1:8080` | Listen address for REST, `/metrics`, and the Control Room. Use `0.0.0.0:8080` when exposing the dashboard from Docker or a LAN. |
| `CERBERUS_GEOIP_DB` | *(unset)* | Path to a MaxMind **GeoLite2-City.mmdb** (or compatible) file. When set and loadable, device records gain optional geo fields for public IPs. |
| `CERBERUS_DATA_DIR` | `./data` | Directory for BuntDB file (see `cmd/cerberus`), IEEE OUI cache, IANA services CSV cache, and related files. |
| `CERBERUS_DB_ONLINE` | *(unset)* | When `1`, `true`, or `yes`, allows automatic download/refresh of IEEE OUI and IANA service registries when local cache is missing or stale. |
| `CERBERUS_ALERTS_CONFIG` | *(unset)* | Path to a YAML or JSON **declarative alerts** file. When unset, built-in defaults apply (same thresholds as before). When set, the file is merged onto defaults and **validated at startup** — invalid config refuses to start. See [`configs/alerts.example.yaml`](../configs/alerts.example.yaml) and [how-to-alerts.md](how-to-alerts.md). |

Interface selection and LRU size are currently set in code (`cmd/cerberus` / `monitor.NewNetworkMonitor`); see root README “Configuration” for pointers.

## Alerts config (declarative)

Three typed rule kinds live in one file:

1. **`thresholds`** — device metrics (`dns_queries`, `unique_targets`, …) with `op` / `value` / `severity` / `enabled`
2. **`baselines`** — rogue DHCP / IPv6 RA / gateway MAC change (enable + optional `known_good` lists)
3. **`anomaly`** — window size, baseline window count, score threshold, enable

Omitted sections keep defaults. Overlay threshold rules **by `id`** (e.g. only disable `target_spread` without re-listing every rule).

```bash
cp configs/alerts.example.yaml configs/alerts.yaml
# edit thresholds / disable noisy rules
CERBERUS_ALERTS_CONFIG=./configs/alerts.yaml sudo ./build/cerberus
```

Scenario-oriented examples (busy LAN, lab, strict infra, security-only, anomaly-focused, quiet) are catalogued in [`configs/README.md`](../configs/README.md).
