# Cerberus documentation

High-level reference for how the project fits together. The code remains the source of truth for field names and edge cases.

| Document | Contents |
|----------|----------|
| [system-overview.md](system-overview.md) | End-to-end architecture: kernel eBPF, ring buffer, monitor, storage, optional GeoIP, databases, HTTP API, anomaly and rule alerting |
| [web-ui.md](web-ui.md) | Control Room layout, hash routes, wireframes per screen, screenshots (`docs/screenshots/`), and which API each view uses |
| [api-reference.md](api-reference.md) | REST paths, embedded static assets, Prometheus metrics |
| [configuration.md](configuration.md) | Environment variables (`CERBERUS_*`) and declarative alerts file |
| [deployment-and-performance.md](deployment-and-performance.md) | Docker/host footprint, example `docker stats`, why CPU/memory stay low at high traffic |
| [ml-anomaly-detection.md](ml-anomaly-detection.md) | “ML-lite” anomaly detector: windows, features, robust z-scores, centroid score, thresholds, API fields, limitations |
| [threat-and-anomaly-patterns.md](threat-and-anomaly-patterns.md) | SYN/SYN-flood-style signals, DDoS-like spikes, probing; what is observed vs blocked; distributed vs per-device alerts |
| [how-to-alerts.md](how-to-alerts.md) | How to trigger rule alerts vs anomaly alerts, default thresholds, deduplication, testing tips |

The root [README.md](../README.md) covers install, prerequisites, troubleshooting, and a compact Control Room wireframe.
