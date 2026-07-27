# Cerberus alerts config examples
#
# Set CERBERUS_ALERTS_CONFIG to any of these files (or a copy you edit).
# Omitted keys merge onto built-in defaults. Invalid configs refuse to start.
#
#   CERBERUS_ALERTS_CONFIG=./configs/alerts.busy-lan.yaml sudo ./build/cerberus
#
# Full field reference: docs/how-to-alerts.md and docs/configuration.md

| File | Use when | What it changes |
|------|----------|-----------------|
| [`alerts.example.yaml`](alerts.example.yaml) | Starting point / full schema | Documents every section with default values |
| [`alerts.busy-lan.yaml`](alerts.busy-lan.yaml) | Busy office / lab LAN (issue #13) | Larger target history; quieter `target_spread` |
| [`alerts.lab-sensitive.yaml`](alerts.lab-sensitive.yaml) | Demos / CI / intentional triggers | Lower volume thresholds so rules fire easily |
| [`alerts.strict-infra.yaml`](alerts.strict-infra.yaml) | Known gateway / DHCP / RA topology | Strict `known_good` baselines for infra IPs |
| [`alerts.security-only.yaml`](alerts.security-only.yaml) | Want DHCP/RA/ARP spoof signals only | Disables volume thresholds + anomaly |
| [`alerts.anomaly-focused.yaml`](alerts.anomaly-focused.yaml) | Behavioral scoring over counters | Disables volume thresholds; keeps anomaly + baselines |
| [`alerts.quiet.yaml`](alerts.quiet.yaml) | Temporary silence / staging | Disables all alert kinds |

Edit placeholders in `alerts.strict-infra.yaml` (DHCP/RA addresses) before using in production.
