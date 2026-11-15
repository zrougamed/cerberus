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
| [active-response.md](active-response.md) | Blocking/counting by MAC or IP range in the kernel: modes, safety rails, policy file, console, API, alerts |
| [industrial-protocols.md](industrial-protocols.md) | Decoding of Modbus/TCP, S7comm, DNP3, EtherNet/IP, BACnet/IP, IEC 104, OPC UA and MQTT, per-device industrial counters and reported identity, and the industrial alert rules and their allow-list |
| [attack-mapping.md](attack-mapping.md) | MITRE ATT&CK for ICS techniques attached to each rule alert, and where they appear |
| [packet-capture.md](packet-capture.md) | In-memory frame ring, pcapng captures around alerts or on demand, access control, API and limits |
| [advisories.md](advisories.md) | Offline advisory bundle from CISA CSAF, building and loading it, how assets are matched, limits |
| [tui.md](tui.md) | Terminal console: `cerberus tui`, views, keys, tokens, footprint |
| [access-control.md](access-control.md) | Roles (viewer, analyst, admin), named API tokens, OIDC sign-in, protecting reads, alert acknowledgement |
| [notifications.md](notifications.md) | Outbound sinks: generic webhook, Slack Incoming Webhooks, Microsoft Teams Adaptive Card / MessageCard, syslog |

The root [README.md](../README.md) covers install, prerequisites, troubleshooting, and a compact Control Room wireframe.
