# Outbound notifications (webhook / Slack / Teams / syslog)

Cerberus can push rule alerts, anomalies, and new-device events to external sinks.
Policy lives under `notifications:` in the declarative alerts config (`CERBERUS_ALERTS_CONFIG`).
Disabled by default.

Delivery is **asynchronous** (never blocks packet processing). A full buffer drops events and logs a line.

## Sinks

| Sink | Config keys | Payload |
|------|-------------|---------|
| **Generic webhook** | `webhook.url` | Raw `Event` JSON (`POST`, `Content-Type: application/json`) |
| **Slack** | `slack.webhook_url` | [Incoming Webhook](https://api.slack.com/messaging/webhooks) with Block Kit |
| **Microsoft Teams** | `teams.webhook_url`, optional `teams.format` | Adaptive Card (default) or legacy MessageCard |
| **Syslog** | `syslog.address`, `syslog.network`, `syslog.tag` | Text line via UDP/TCP/unix |

Enable at least one sink when `notifications.enabled: true`.

## Shared filters

| Field | Meaning |
|-------|---------|
| `enabled` | Master switch |
| `min_severity` | Drop below `low` / `medium` / `high` |
| `kinds` | Empty = all; otherwise subset of `rule`, `anomaly`, `new_device` |
| `webhook.timeout_seconds` | HTTP client timeout for webhook / Slack / Teams (default **5**) |

## Event JSON (generic webhook)

```json
{
  "kind": "rule",
  "severity": "high",
  "title": "Rule alert: dns_query_volume",
  "message": "DNS queries exceeded threshold",
  "device_mac": "AA:BB:CC:DD:EE:FF",
  "device_ip": "192.168.1.50",
  "vendor": "Raspberry Pi Foundation",
  "rule": "dns_query_volume",
  "observed_at": "2026-08-03T17:00:00Z"
}
```

Anomaly events set `kind: "anomaly"` and may include `score`. New devices use `kind: "new_device"`.

## Slack setup

1. Create an [Incoming Webhook](https://api.slack.com/messaging/webhooks) for your workspace/channel.
2. Put the URL in config:

```yaml
notifications:
  enabled: true
  min_severity: medium
  slack:
    webhook_url: https://hooks.slack.com/services/T.../B.../...
```

Messages include a header, severity, body, and fact fields (MAC, IP, rule, score, …).

## Microsoft Teams setup

### Adaptive Card (default) — Power Automate / Workflows

1. In Teams, create a workflow such as **“Post to a channel when a webhook request is received”**.
2. Copy the HTTP POST URL into `teams.webhook_url`.
3. Leave `format: adaptive` (or omit `format`).

```yaml
notifications:
  enabled: true
  teams:
    webhook_url: https://prod-....logic.azure.com:443/workflows/.../triggers/manual/paths/invoke?...
    format: adaptive
```

### Legacy MessageCard — classic Office 365 connector

If you still use a classic Incoming Webhook connector:

```yaml
notifications:
  enabled: true
  teams:
    webhook_url: https://outlook.office.com/webhook/...
    format: message_card
```

## Example config

See [`configs/alerts.notifications.yaml`](../configs/alerts.notifications.yaml) and the full schema in [`configs/alerts.example.yaml`](../configs/alerts.example.yaml).

```bash
cp configs/alerts.notifications.yaml configs/alerts.yaml
# edit slack.webhook_url and/or teams.webhook_url
CERBERUS_ALERTS_CONFIG=./configs/alerts.yaml sudo ./build/cerberus
```

## Related

- [how-to-alerts.md](how-to-alerts.md) — when rule / anomaly / new-device events fire  
- [configuration.md](configuration.md) — `CERBERUS_ALERTS_CONFIG`  
- [configs/README.md](../configs/README.md) — scenario examples  
