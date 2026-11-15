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
| **Syslog** | `syslog.address`, `syslog.network`, `syslog.tag`, `syslog.format` | Text, CEF or LEEF over UDP, TCP, TLS or a unix socket |

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

Rule events whose rule maps to MITRE ATT&CK for ICS add
`"techniques": ["T0843 Program Download", "T0889 Modify Program"]`. Slack
and Teams show them as an "ATT&CK for ICS" fact; syslog appends
`techniques=T0843,T0889`. See [attack-mapping.md](attack-mapping.md).

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

Messages include a header, severity, body, and fact fields (MAC, IP, rule, ATT&CK for ICS techniques, score, …).

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

## Syslog formats and TLS

`syslog.format` picks the message body:

| Format | Body |
|--------|------|
| `text` (default) | `cerberus kind=rule severity=high title="..." message="..." mac=... ip=... rule=... techniques=T0843,T0889` |
| `cef` | ArcSight CEF 0: `CEF:0|Cerberus|Cerberus|<version>|<rule or kind>|<title>|<severity>|<extension>` |
| `leef` | IBM QRadar LEEF 2.0 with the tab delimiter: `LEEF:2.0|Cerberus|Cerberus|<version>|<rule or kind>|<attributes>` |

Severity maps to 3 (low), 6 (medium) and 9 (high) on the 0-10 scale both
formats use. The event id is the rule (`s7_program`, `watchlist:c2`) or, for
anomalies and new devices, the kind, so SIEM rules can key on it.

| Field | CEF key | LEEF key |
|-------|---------|----------|
| Observed time | `rt` (epoch ms) | `devTime` + `devTimeFormat` |
| Kind | `cat` | `cat` |
| Message | `msg` | `msg` |
| Device IP | `src` (IPv4) or `c6a2` (IPv6) | `src` |
| Device MAC | `smac` | `srcMAC` |
| Rule | `cs1` (label `Rule`) | `rule` |
| OUI vendor | `cs2` (label `Vendor`) | `vendor` |
| ATT&CK for ICS | `cs3` (label `ATT&CK for ICS`) | `techniques` |
| Anomaly score | `cfp1` | `score` |

CEF values escape `\`, `=` and line breaks, and header fields escape `\` and
`|`, as the CEF spec requires. LEEF values have tabs and line breaks replaced
by spaces.

`syslog.network: tls` sends RFC 5424 messages over TLS with RFC 5425
octet-counting framing (port 6514 is the usual one). The collector's
certificate is checked against the system roots, or only against the CA in
`syslog.ca_file` when it is set; `syslog.server_name` overrides the name
checked when it differs from the address. TLS 1.2 is the minimum. A failed
write drops that message and reconnects on the next one; connect and write
each time out after 5 seconds, so a dead collector does not hold up the
other sinks.

```yaml
notifications:
  enabled: true
  syslog:
    network: tls
    address: siem.plant.example:6514
    format: cef
    ca_file: /etc/cerberus/siem-ca.pem
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
