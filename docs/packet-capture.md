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
  buffer_mb: 32             # ... and in memory, whichever is reached first
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
| `GET /api/v1/captures` | Status (`enabled`, `interfaces`, `buffer_packets`, `buffer_bytes`, `buffer_oldest`, `pending`, `skipped`, `kernel_drops`) and `captures` (id, created_at, reason, rule, alert_id, address, from, to, packets, bytes, drops) |
| `GET /api/v1/captures/{id}` | Bearer token. The pcapng file |
| `DELETE /api/v1/captures/{id}` | Bearer token |
| `POST /api/v1/captures` | Bearer token. `{"address": "...", "seconds": N}`, N up to `buffer_seconds` |

Metrics: `cerberus_capture_buffer_packets`, `cerberus_capture_buffer_bytes`,
`cerberus_capture_kernel_drops_total`, `cerberus_capture_skipped_total`.

## How it works

Each capture interface gets a `TPACKET_V3` packet ring (`CAP_NET_RAW`,
which Cerberus already needs for BPF): 4 blocks of 1 MiB that the kernel
fills and hands over whole. The reader wakes once per block, or every 100 ms
on a quiet link, not once per frame. A one-instruction classic BPF filter
on the socket truncates frames to `snaplen` in the kernel, so nothing that
would be thrown away is copied.

Frames are then copied once into the history ring: a single preallocated
`buffer_mb` arena with each frame stored inline behind a 16-byte header.
Storing a frame allocates nothing, so memory stays at `buffer_mb` (plus
4 MiB of kernel ring per interface) and the garbage collector has no
per-frame work. Timestamps come from the kernel.

Measured on a loopback flood with the reader limited to two CPUs:

| | Before (one read per frame) | Now |
|---|---|---|
| CPU per 64-byte frame | 1,504 ns | 50 ns |
| CPU per 1,400-byte frame | 2,264 ns | 212 ns |
| Frames captured per frame sent | about half missed, silently | all but 0.01% |
| Storing a 64-byte frame in the history | 98 ns, 1 heap allocation | 43 ns, none |
| Storing a 1,514-byte frame in the history | 449 ns, 1 heap allocation | 198 ns, none |

The TC program is not involved: a second BPF ring buffer for full frames
would add verifier risk on every supported kernel for no gain over the
mapped ring.

## Limits

- Any capture can fall behind under enough load. When the kernel drops
  frames because the ring is full, Cerberus counts them
  (`cerberus_capture_kernel_drops_total`) and records the count in each
  capture whose window they fall in (`drops` in the API, "Incomplete" on
  the Captures page), so a capture never looks complete when it is not.
- Only Ethernet interfaces are supported.
- Captures waiting for their follow-up window are dropped on shutdown.
