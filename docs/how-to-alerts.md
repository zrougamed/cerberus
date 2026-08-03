# How to trigger and use alerts

Cerberus exposes **two kinds** of alerts in the API and Control Room:

| Kind | Where in UI | Endpoint | What fires them |
|------|-------------|----------|-----------------|
| **Rule-based** | **Rule alerts** | `GET /api/v1/alerts` | Declarative **threshold** rules (DNS/TCP/target spread by default) plus **security baselines** (rogue DHCP/RA, gateway MAC) |
| **Anomaly (ML-lite)** | **Anomalies** | `GET /api/v1/anomalies` | Global 30-second windows vs a learned baseline (combined score ≥ threshold) |

Policy is loaded from **`CERBERUS_ALERTS_CONFIG`** (YAML/JSON) or built-in defaults. See [`configs/`](../configs/README.md) for scenario examples, [`configs/alerts.example.yaml`](../configs/alerts.example.yaml) for the full schema, and [configuration.md](configuration.md).

---

## 1. Threshold alerts (`AlertEvent`)

Evaluation runs whenever a device is updated (`evaluateAlerts` in `internal/monitor`). Defaults (when no config file is set):

| Rule ID | Metric | Condition | Default |
|---------|--------|-----------|---------|
| `dns_query_volume` | `dns_queries` | `gt` | **200** |
| `tcp_connection_volume` | `tcp_connections` | `gt` | **500** |
| `target_spread` | `unique_targets` | `gt` | **18** |

`unique_targets` is the length of a rolling list of destination IPs per device (`target_history_size`, default **20**). The threshold value must stay **below** that size or the rule never fires.

**Deduplication:** For each `(device MAC, rule)` pair, Cerberus emits **one** alert the first time the condition becomes true. It does **not** spam a new row on every packet while the condition stays true. When the condition **clears**, the internal latch resets; crossing again can produce a **new** alert.

### Tune or disable without rebuilding

```yaml
# configs/alerts.yaml — overlay only what you need
target_history_size: 40
thresholds:
  - id: target_spread
    value: 30          # raise for busy LANs
  # or silence false positives:
  # - id: target_spread
  #   enabled: false
```

```bash
CERBERUS_ALERTS_CONFIG=./configs/alerts.yaml sudo ./build/cerberus
```

Invalid configs **fail startup** (fail-closed).

### How to trigger them (testing / demos)

1. **`dns_query_volume`** — From one MAC, generate more DNS queries than the configured threshold.
2. **`tcp_connection_volume`** — Open more TCP connections than the threshold from one source MAC.
3. **`target_spread`** — Contact more distinct destination IPs than the threshold (within the rolling history window).

**View:** Control Room → **Rule alerts**, or `curl -s http://127.0.0.1:8080/api/v1/alerts`.

### Adding a threshold rule

Append a new `id` under `thresholds` using a known metric (`dns_queries`, `tcp_connections`, `udp_connections`, `unique_targets`, `icmp_packets`, `http_requests`, `tls_connections`, `dns_correlated`) and an op (`gt`, `gte`, `lt`, `lte`, `eq`). No rebuild required for policy changes; new **metrics** still need code.

### Security baselines

Also appear as rule alerts. Configure under `baselines:` — enable/disable and optional `known_good` IP lists (non-empty → strict mode).

| Rule ID | Meaning |
|---------|---------|
| `rogue_dhcp_server` | Unexpected DHCP server reply |
| `rogue_ipv6_ra_source` | Unexpected IPv6 Router Advertisement |
| `gateway_mac_changed` | DHCP-server IP claimed by a new MAC |

---

## 2. Anomaly alerts (`AnomalyAlert`)

Configured under `anomaly:` (window, baseline window count, score threshold). Defaults: **20** completed 30-second windows (~10 minutes), then score ≥ **3.5** records an alert. Set `enabled: false` to turn the detector off.

### How to trigger them (testing / demos)

- **SYN / port-scan style traffic:** Many SYN packets, high SYN rate, many uncommon destination ports, or sharp jumps in overall event rate vs baseline (e.g. `hping3`, `nmap -sS`, or lab SYN flood tools **only on networks you own**).
- **Volume spikes:** Sudden bulk DNS, HTTP, or mixed traffic that pushes `packet_rate`, per-protocol rates, or **packet_rate_slope** far from the first baseline windows.

**View:** Control Room → **Anomalies**, or `GET /api/v1/anomalies`.

**Warm-up:** Until baseline is ready, you will see `warming_up` and no anomaly scores for alerting.

See [threat-and-anomaly-patterns.md](threat-and-anomaly-patterns.md) and [ml-anomaly-detection.md](ml-anomaly-detection.md).

### SYN floods and DDoS (short version)

- There is **no** separate “SYN flood” or “DDoS” rule ID. Both usually appear as **anomaly alerts** when related features jump vs baseline.
- Cerberus **does not block** traffic; it **observes** and **scores**.

---

## 3. Outbound notifications (webhook / Slack / Teams / syslog)

Optional sinks under `notifications:` push the same events off-box. Disabled by default.

| Sink | Config | Notes |
|------|--------|-------|
| Generic webhook | `webhook.url` | `POST` raw Event JSON |
| **Slack** | `slack.webhook_url` | Incoming Webhook + Block Kit |
| **Microsoft Teams** | `teams.webhook_url` | Adaptive Card (default) or `format: message_card` |
| Syslog | `syslog.address` | e.g. `127.0.0.1:514` with `network: udp` |

Shared filters: `min_severity`, `kinds` (`rule` / `anomaly` / `new_device`).

Full setup (Slack app URL, Teams Workflow URL, payload shapes): **[notifications.md](notifications.md)**.  
Example: [`configs/alerts.notifications.yaml`](../configs/alerts.notifications.yaml).

Delivery is asynchronous (never blocks packet processing). Full buffers drop events with a log line.

---

## 4. Prometheus (optional)

`GET /metrics` exposes packet and device counters. You can **route Prometheus alerts** on those series for ops-level paging—outside Cerberus’s built-in alert list.

---

## 5. Quick checklist

| Goal | Action |
|------|--------|
| See rule alerts | Exceed configured DNS / TCP / target thresholds from one device, then open **Rule alerts** |
| Silence `target_spread` | `enabled: false` (or raise `value` / `target_history_size`) in alerts config |
| See anomaly alerts | Wait for baseline, then generate traffic very different from the first warm-up windows |
| Reset rule latch | Let counts drop under threshold; next crossing can alert again |
| No alerts at all | Quiet traffic; or disable rules / anomaly in config |
| Webhook / Slack / Teams | Enable `notifications` and set `webhook.url`, `slack.webhook_url`, and/or `teams.webhook_url` — see [notifications.md](notifications.md) |

---

## Related

- [api-reference.md](api-reference.md) — JSON shapes  
- [web-ui.md](web-ui.md) — where alerts appear in the Control Room  
- [notifications.md](notifications.md) — Slack / Teams / webhook / syslog  
- [configuration.md](configuration.md) — `CERBERUS_*` including `CERBERUS_ALERTS_CONFIG`  
