# Industrial protocols

Cerberus decodes industrial control protocols in user space, from the first
128 bytes of payload that the TC program already copies into every TCP and
UDP event. No BPF change and no extra kernel work is involved, so enabling it
costs nothing on networks that don't carry this traffic.

Supported today: **Modbus/TCP** (TCP 502). Planned: S7comm, DNP3,
EtherNet/IP + CIP, BACnet/IP, IEC 104, OPC UA, MQTT and PROFINET DCP (see
the `industrial` label on the issue tracker).

## What is recorded

Every decoded message updates the `industrial` object of the device that sent
it, keyed by protocol:

```json
"industrial": {
  "modbus": {
    "requests": 42,
    "responses": 0,
    "exceptions": 0,
    "operations": { "read": 41, "write": 1 },
    "functions": { "read_holding_registers": 40, "write_multiple_registers": 1, "read_device_identification": 1 },
    "peers": ["10.20.0.50"],
    "last_seen": "2026-11-14T19:42:29Z"
  }
}
```

- `requests` are messages the device sent as a client (HMI, SCADA server,
  engineering workstation). `operations` and `functions` count requests only.
- `responses` are messages it sent as a server (PLC, RTU, gateway);
  `exceptions` counts error replies among them.
- `peers` keeps the 32 most recent remote addresses, newest last.

The device page in the Control Room shows this under **Industrial
protocols**, with writes and diagnostics highlighted.

Prometheus gets one counter across all devices:

```
cerberus_industrial_messages_total{protocol="modbus",class="write",direction="request"} 1
```

## Modbus/TCP

A frame is accepted only when the MBAP header is consistent: protocol id 0,
length between 2 and 254, and a non-zero function code. A bare ACK or TLS on
port 502 is ignored. Direction comes from the port: traffic to 502 is a
request, traffic from 502 is a response. A function code with the high bit
set is always an error reply, whichever side it comes from.

| Class | Function codes |
|-------|----------------|
| read | 1, 2, 3, 4, 7, 11, 12, 17, 20, 24, and 43 with MEI type 14 (Read Device Identification) |
| write | 5, 6, 15, 16, 21, 22, 23 |
| diagnostic | 8 (Diagnostics, includes restart and listen-only mode), 43 with any other MEI type |
| other | anything else, including user-defined codes |

For reads and writes the start address and count are extracted; for 23
(read/write multiple) the written range is reported.

### Alerts

| Rule | Fires on | Default |
|------|----------|---------|
| `modbus_write` | A write request from a source not in `allowed_sources` | on, high |
| `modbus_diagnostic` | A diagnostic request from a source not in `allowed_sources` | on, high |

Example message:
`Modbus write_multiple_registers from 10.20.0.10 to 10.20.0.50 unit 1, address 100 count 2`

An alert is raised at most once per `realert_seconds` (default 3600) for the
same source device, target address and unit id. Allowed sources are still
counted, just never alerted on. On a site where the SCADA server writes all
day, list it in `allowed_sources` and every other writer stands out.

```yaml
industrial:
  modbus_write:
    enabled: true
    severity: high              # low | medium | high
    allowed_sources:            # addresses or CIDRs
      - 10.20.0.10              # SCADA server
      - 10.20.5.0/28            # engineering workstations
    realert_seconds: 3600       # 0 alerts on every write
  modbus_diagnostic:
    enabled: true
    severity: high
```

Invalid severities, negative `realert_seconds` or unparsable addresses refuse
to start, like the rest of the alerts file.

## Limits

- Only the first 128 bytes of each segment are seen. One Modbus frame per
  segment is decoded; a second frame packed in the same segment is not.
- Modbus over a non-standard port is not detected.
- Modbus has no authentication, so `allowed_sources` is matched on IP
  address. Anyone who can spoof the SCADA server's address can write without
  an alert. Pair it with the `gateway_mac_changed` baseline and switch port
  security.
