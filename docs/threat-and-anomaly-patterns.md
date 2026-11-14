# Threat-relevant patterns Cerberus can surface

Cerberus is a **visibility and behavioral-anomaly** tool, not a full IDS/IPS product. It does not label packets with vendor threat names, and detections never block anything on their own. Blocking is a separate, explicit step: operator-defined policy rules ([active-response.md](active-response.md)). What it **does** do is measure **metadata** (counts, ports, rates, L7 snippets) and raise **rule alerts** or **ML-lite anomaly scores** when traffic **shape** diverges from a recently learned baseline.

The behaviors below are described in terms of **what the pipeline can show** and **what that often lines up with** in real networks. Always confirm with your own tools, captures, and policy.

---

## 1. SYN scans and SYN floods

**What Cerberus measures**

- Every TCP event can be **classified** by flags; SYN-without-ACK is labeled as `TCP_SYN` traffic type (`internal/monitor` classification).
- The anomaly detector tracks **`tcp_syn_rate`**: SYN packets per second in each 30-second window.
- It also tracks **`unusual_port_count`** (distinct destination ports outside a small “common services” set) and **`port_entropy`** (how spread out destination ports are).

**How that relates to abuse**

- **Horizontal scans** (many destinations or many ports) often drive **high SYN rate**, **many uncommon ports**, and **high entropy**.
- **SYN floods** toward one or many targets drive **very high `tcp_syn_rate`** and often **high overall `packet_rate`**.

**Plain-language UI** calls this out (for example handshakes “common with port scans or SYN floods”) when those features dominate the score.

### SYN flood detection (expectations)

Cerberus does **not** emit a dedicated alert titled “SYN flood.” It has **no SYN cookie**, **no rate limiting**, and **no mitigation**—only **observation**.

What you get instead:

| Signal | Where |
|--------|--------|
| Very high **TCP SYN rate** and/or **overall event rate** in a 30s window | **Anomalies** (`tcp_syn_rate`, `packet_rate`, contributions in JSON/UI) |
| SYN packets counted as **`TCP_SYN`** traffic type | Aggregates, device **traffic_type_counts**, patterns |

So “SYN flood detection” here means: **behavior changed sharply in ways consistent with many SYNs** vs your short learned baseline—not a vendor IDS verdict.

---

## 2. DDoS-like or volumetric spikes

**What Cerberus measures**

- **`packet_rate`**, per-protocol rates (`dns_rate`, `http_rate`, `tls_rate`), and **`packet_rate_slope`** (jump or drop vs the previous window).
- **Rule alerts** can fire on **high DNS query volume**, **high TCP connection counts**, or **many unique targets** per device when you exceed configured thresholds (`internal/monitor` alert rules).

**How that relates to abuse**

- A **sudden flood** of events (any mix of protocols) pushes **aggregate rate** and **slope**.
- **Reflected or application-layer floods** may show up as spikes in **DNS**, **HTTP**, or **TLS** rates depending on what is actually on the wire in the sampled payload window.

Cerberus does **not** distinguish “attack” vs “viral legitimate traffic” by itself; both can look like a spike. The value is **fast situational awareness** and **correlation** with device, port, and host/SNI fields in the dashboard.

### DDoS (expectations)

**Volumetric DDoS** (a huge jump in packets/events on the monitored link) usually shows up in **anomaly scoring**: high **`packet_rate`**, **`packet_rate_slope`**, and often several protocol rates at once. You see it on the **Anomalies** page and in **`GET /api/v1/anomalies`**.

**Per-device rule alerts** (`dns_query_volume`, `tcp_connection_volume`, `target_spread`) only help when **one observed source MAC** crosses thresholds. A **distributed** attack spread across many clients may **not** trip those rules much, while the **global** anomaly detector can still spike if **aggregate** traffic shape changes vs baseline.

**Application-layer** floods (HTTP/DNS/TLS-heavy) may elevate **`http_rate`**, **`dns_rate`**, or **`tls_rate`** in the anomaly vector if that traffic is present in the capture path.

Again: **no automatic blocking** and **no “this is a DDoS” label**, only statistical deviation and counters. To act on a finding, add a policy rule ([active-response.md](active-response.md)).

---

## 3. Probing, scanning, and “noisy” clients

**What Cerberus measures**

- **Unusual destination ports** and **port diversity** (entropy) in the anomaly feature vector.
- **Per-device `targets`** and **service maps** in `DeviceInfo` (what destinations and ports were seen).

**How that relates to abuse**

- **Port scanning** and **service probing** often produce **many rare ports** and **unusual entropy** compared to a calm baseline.
- **Lateral movement** may not be uniquely labeled, but **new targets** and **spread** contribute to **rule alerts** (`target_spread`) and stand out in the **device detail** view.

---

## 4. Reverse tunnels, covert channels, and “beacon” behavior (indirect signals)

Cerberus **does not** implement a dedicated “reverse tunnel detector” (no SSH `-R` parser, no ICMP tunnel classifier, no DNS-tunnel ML model).

You can still **notice conditions that are worth investigating**, using the same aggregates:

| Signal | Where it shows up |
|--------|-------------------|
| Long-lived or repeated connections to **non-standard ports** | Device **services**, **targets**, anomaly **unusual_port_count** / **entropy** |
| **TLS** to unexpected hosts | **TLS SNIs**, **TLS versions**, TLS rate in anomalies |
| **DNS** oddities | Query types, response codes, correlated domains |
| **Sustained outbound** volume to few IPs | **Targets**, **TCP** counts, **rule alerts** on connection volume |
| **DoH/DoT-style** hints | **Encrypted DNS** bucket heuristics (known resolvers / ports) |

Framing: these are **hypothesis generators**, not verdicts. A reverse shell over TLS to `443` can look like normal HTTPS unless SNI/behavior is unusual for that host.

---

## 5. Where to look in the product

| Goal | Start here |
|------|------------|
| **Spike in odd TCP behavior** | Control Room **Anomalies**, plain summary + technical details; **Metrics** `/metrics` |
| **One host hammering many destinations** | **Rule alerts** (`target_spread`, `tcp_connection_volume`), **device detail** targets |
| **DNS-heavy abuse or misuse** | **Rule alert** `dns_query_volume`, **summary** DNS stats, device **DNS** maps |
| **Deep forensics** | **Raw JSON** API, **device** drill-down, optional **GeoIP** on public IPs |

---

## 6. Related documentation

- [ml-anomaly-detection.md](ml-anomaly-detection.md) — feature vector, scoring, thresholds  
- [system-overview.md](system-overview.md) — pipeline from eBPF to API  
- [api-reference.md](api-reference.md) — JSON fields for automation  

---

**Summary:** Cerberus is built to **detect SYN-heavy and volume/entropy anomalies**, **surface scan-like port behavior**, and **alert on thresholded abuse of DNS/TCP/target spread**. **Reverse tunnels** are not named as such; use **device- and protocol-level** views plus anomalies as **leads**, not automatic classifications.
