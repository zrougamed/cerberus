# Industrial protocols

Cerberus decodes industrial control protocols in user space, from the first
128 bytes of payload that the TC program already copies into every TCP and
UDP event. No BPF change and no extra kernel work is involved, so enabling it
costs nothing on networks that don't carry this traffic.

Supported today: **Modbus/TCP** (TCP 502), **S7comm** (ISO-on-TCP, TCP
102, with S7comm-plus detected and counted) and **DNP3** (TCP and UDP
20000), **EtherNet/IP + CIP** (TCP and UDP 44818), **BACnet/IP** (UDP
47808), **IEC 60870-5-104** (TCP 2404), **OPC UA** binary (TCP 4840) and
**MQTT** (TCP 1883). Planned:
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

## S7comm

Port 102 carries TPKT + COTP (RFC 1006). IEC 61850 MMS uses the same
framing, so S7 is only claimed when it is unambiguous:

- COTP connection request/confirm whose destination TSAP is two bytes with a
  connection type of 1 (PG), 2 (OP) or 3 (S7 basic). The rack and slot are
  taken from the second byte and counted in `details`, e.g.
  `"details": {"rack 0 slot 2": 4}`.
- COTP data carrying an S7 header (protocol id `0x32`, reserved bytes zero,
  ROSCTR job, ack, ack-data or userdata).
- S7comm-plus (protocol id `0x72`, version 1 to 3) is counted under
  `s7comm_plus` and never alerted on; its payload is integrity protected and
  not decoded.

Direction comes from the S7 header (job vs ack), not the port. An ack-data
with a non-zero error class counts as an error reply.

| Class | Functions |
|-------|-----------|
| read | read_var, start_upload, upload, end_upload |
| write | write_var |
| control | plc_stop, plc_start (PI service `P_PROGRAM`), other PI services |
| program | request_download, download_block, download_ended, delete_block (`_DELE`), insert_block (`_INSE`), compress_memory (`_GARB`), copy_ram_to_rom (`_MODU`) |
| other | setup_communication, cpu_services, userdata, cotp_connect |

### Alerts

| Rule | Fires on | Default |
|------|----------|---------|
| `s7_write` | write_var | on, medium |
| `s7_control` | PLC stop, start and other PI services | on, high |
| `s7_program` | Download, delete, insert, compress, copy to ROM | on, high |

They take the same `allowed_sources` and `realert_seconds` options as the
Modbus rules. S7 has no unit id, so re-alerting is per source and target.

Example: `S7comm plc_stop from 10.20.0.10 to 10.20.0.50`

## DNP3

A frame is accepted only when the link header starts with `05 64`, declares
a length of at least 5 and its CRC matches. Link frames without user data
(reset link, link status) count as `link_layer`. For user data the
transport and application headers are read from the first block; the
outstation address is counted in `details` (`"outstation 10": 42`) and the
direction comes from the function code (129 and up are responses). A
response with any of the low three IIN2 bits set (function not supported,
object unknown, parameter error) counts as an error reply.

| Class | Functions |
|-------|-----------|
| read | read, get_file_info |
| write | write, freeze_clear |
| control | select, operate, direct_operate, direct_operate_no_ack, start_application, stop_application |
| diagnostic | cold_restart, warm_restart, initialize_data, initialize_application, save_configuration, disable_unsolicited |
| program | delete_file, activate_config |
| other | confirm, freezes, enable_unsolicited, time sync, file open/close, authentication, responses |

`disable_unsolicited` is in the diagnostic class because it is a known way to
stop an outstation from reporting changes to its master.

| Rule | Fires on | Default |
|------|----------|---------|
| `dnp3_control` | control class requests | on, high |
| `dnp3_diagnostic` | restarts, initialisation, save configuration, disable unsolicited | on, high |

Example: `DNP3 direct_operate from 10.20.0.10 to 10.20.0.70 (outstation 10)`

## EtherNet/IP and CIP

The 24-byte encapsulation header must name a known command, have the
options field at zero and, for requests, status zero. For SendRRData and
SendUnitData the CIP request inside the data item is decoded: service code
and the class from the path. One level of Unconnected Send (how engineering
tools reach a controller through a comms module) is unwrapped, so a tag
write routed that way is still seen as `write_tag`.

| Class | Services |
|-------|----------|
| read | get_attribute(s)_*, read_tag, read_tag_fragmented, get_member |
| write | set_attribute(s)_*, write_tag, write_tag_fragmented, read_modify_write_tag, create, delete |
| control | reset, start, stop |
| other | forward_open/close, unconnected_send, multiple_service_packet, session commands |

ListIdentity replies (the answer to a broadcast that most engineering tools
send) are stored on the device as `asset`: vendor, model (product name),
firmware revision, serial and device type. The device page shows them under
**Reported identity**.

| Rule | Fires on | Default |
|------|----------|---------|
| `enip_write` | CIP writes, including Logix tag writes | on, medium |
| `enip_control` | reset, start, stop (reset on the identity object reboots the device) | on, high |

Implicit I/O on UDP 2222 is not decoded.

## BACnet/IP

BVLC type `0x81`, then the NPDU (routing information is skipped) and the
APDU type and service. Direction comes from the APDU type: confirmed and
unconfirmed requests are requests, acks, errors, rejects and aborts are
replies. I-Am and I-Have are announcements from the device itself and count
as server traffic. I-Am fills the device `asset` with its instance number
and vendor id, and the instance goes into `details` (`"device 260001"`).

| Class | Services |
|-------|----------|
| read | read_property, read_property_multiple, read_range, atomic_read_file |
| write | write_property, write_property_multiple, create/delete object, list element changes, write_group, BDT/FDT changes |
| control | device_communication_control, reinitialize_device |
| program | atomic_write_file |

| Rule | Default |
|------|---------|
| `bacnet_write` | on, medium |
| `bacnet_control` | on, high |

## IEC 60870-5-104

APCI start byte `0x68` and a length of 4 to 253. S- and U-frames
(STARTDT, STOPDT, TESTFR) are counted by name. For I-frames the ASDU type
and cause of transmission are read: activation, deactivation and request
are commands, anything else is a reply. Monitoring types (1 to 44) are
always replies and counted as `monitor_data`. A negative confirmation counts
as an error reply. The common address goes into `details`.

| Class | Types |
|-------|-------|
| read | interrogation, counter_interrogation, read |
| write | parameter_* (110 to 113) |
| control | single/double/regulating step/setpoint/bitstring commands, with and without time tag (45 to 51, 58 to 64) |
| diagnostic | reset_process (105) |

| Rule | Default |
|------|---------|
| `iec104_control` | on, high |
| `iec104_diagnostic` | on, high |

## OPC UA

The 8-byte message header (HEL, ACK, ERR, OPN, MSG, CLO, RHE) is checked.
For OPN the security policy URI, which is always sent in the clear, goes
into `details` (`"security policy Basic256Sha256"`). For MSG the service
type id is read when the channel is not encrypted: read, write, call,
browse and session services are named, an encrypted body stays `message`.

| Rule | Fires on | Default |
|------|----------|---------|
| `opcua_write` | write requests on unencrypted channels | on, medium |
| `opcua_insecure` | a client opening a channel with `SecurityPolicy#None` | on, medium |

## MQTT

Fixed header and remaining length are validated; CONNECT must name `MQTT`
or `MQIsdp` with protocol level 3 to 5. The client id from CONNECT and the
topic from PUBLISH go into `details` (capped at 16 entries per device).
PUBLISH from a client counts as a write, SUBSCRIBE as a read.

| Rule | Fires on | Default |
|------|----------|---------|
| `mqtt_anonymous` | CONNECT without a username | on, medium |

MQTT over TLS (8883) is encrypted and not decoded.

## Limits

- DNP3 objects (which point is operated, with what value) are past the
  first header and not decoded. Data block CRCs are not checked.
- Only the first 128 bytes of each segment are seen. One Modbus frame per
  segment is decoded; a second frame packed in the same segment is not.
- Every protocol is matched on its registered port only.
- SUBSCRIBE topics are not extracted: without connection state the MQTT
  version, and so the packet layout, is unknown.
- S7 userdata (SZL reads, block info, clock, passwords) is counted but not
  decoded yet; that comes with the asset inventory work.
- Modbus has no authentication, so `allowed_sources` is matched on IP
  address. Anyone who can spoof the SCADA server's address can write without
  an alert. Pair it with the `gateway_mac_changed` baseline and switch port
  security.
