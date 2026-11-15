# Packet capture

Cerberus can keep a short history of raw frames in memory and save it as a
pcapng file when an alert fires, or on demand. Open the file in Wireshark
to see exactly what happened. It is **off by default**: it reads every
frame on the capture interfaces, which costs CPU and memory that the rest
of Cerberus does not need.

## Turning it on

In the alerts config file (`CERBERUS_ALERTS_CONFIG`):

```yaml
capture:
  enabled: true
  interfaces: []            # empty: the interfaces Cerberus is attached to
  snaplen: 1518             # bytes kept per frame
  buffer_seconds: 120       # ring length in time ...
  buffer_mb: 64             # ... and in memory, whichever is reached first
  on_alert:
    enabled: true
    min_severity: high      # alerts at or above this get a capture
    before_seconds: 30      # history saved from before the alert
    after_seconds: 10       # follow-up traffic saved after it
    min_interval_seconds: 300   # at most one capture per device per 5 minutes
  max_files: 50             # oldest captures are deleted past either limit
  max_total_mb: 512
  dir: ""                   # default: <data dir>/captures
```

Restart Cerberus after changing it. The startup log names the interfaces
and the capture directory.

## What gets saved

- **On alert**: when a rule alert at or above `min_severity` fires, the
  frames to or from the alerting device's address between
  `before_seconds` before and `after_seconds` after the alert are written to
  `<id>.pcapng`. The alert gets a `capture_id` and the alerts table links to
  the **Captures** page. At most 16 captures wait for their follow-up window
  at once; alerts past that, or inside `min_interval_seconds` for the same
  device, are counted in `cerberus_capture_skipped_total` instead.
- **On demand**: the **Captures** page, or `POST /api/v1/captures` with
  `{"address": "10.20.0.50", "seconds": 60}`, saves the last N seconds of the
  buffer, for one address or (without `address`) everything.

Files are pcapng with one interface block per capture interface, microsecond
timestamps and the original frame length, so truncated frames show as such
in Wireshark. IPv4, IPv6 and ARP addresses are matched, through 802.1Q and
802.1ad VLAN tags.

## Access

Captures hold full packet payloads, so:

- files and their directory are created owner-only (0600 / 0700);
- downloading (`GET /api/v1/captures/{id}`), deleting and capturing on
  demand all need the API token, even though the list of captures is
  readable like the rest of the API;
- capture ids are random 16-hex strings and are checked before any file is
  touched.

## API and metrics

| Request | Description |
|---------|-------------|
| `GET /api/v1/captures` | Status (`enabled`, `interfaces`, `buffer_packets`, `buffer_bytes`, `buffer_oldest`, `pending`, `skipped`) and `captures` (id, created_at, reason, rule, alert_id, address, from, to, packets, bytes) |
| `GET /api/v1/captures/{id}` | Bearer token. The pcapng file |
| `DELETE /api/v1/captures/{id}` | Bearer token |
| `POST /api/v1/captures` | Bearer token. `{"address": "...", "seconds": N}`, N up to `buffer_seconds` |

Metrics: `cerberus_capture_buffer_packets`, `cerberus_capture_buffer_bytes`,
`cerberus_capture_skipped_total`.

## How it works, and limits

Frames are read in user space from an `AF_PACKET` socket per interface
(`CAP_NET_RAW`, which Cerberus already needs for BPF). The TC program is not
involved: a second BPF ring buffer for full frames would add verifier risk
on every supported kernel, and capture is meant to be switched on for an
incident rather than run everywhere all the time. Each frame is copied once
into the ring; memory is bounded by `buffer_mb`.

- Frames are read with one system call each. On a busy link (hundreds of
  thousands of packets per second) the reader can fall behind and the
  kernel drops frames from the socket queue; captures are then incomplete.
- Only Ethernet interfaces are supported.
- Captures waiting for their follow-up window are dropped on shutdown.
