# Industrial protocols

Cerberus decodes industrial control protocols in user space, from the first
128 bytes of payload that the TC program already copies into every TCP and
UDP event. No BPF change and no extra kernel work is involved, so enabling it
costs nothing on networks that don't carry this traffic.

Supported today: **Modbus/TCP** (TCP 502), **S7comm** (ISO-on-TCP, TCP
102, with S7comm-plus detected and counted) and **DNP3** (TCP and UDP
20000), **EtherNet/IP + CIP** (TCP and UDP 44818), **BACnet/IP** (UDP
47808), **IEC 60870-5-104** (TCP 2404), **OPC UA** binary (TCP 4840) and
**MQTT** (TCP 1883) and **PROFINET DCP** (Ethernet, ethertype 0x8892). Planned:
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

## Asset inventory

Each device that speaks one of these protocols, or reports an identity, is
listed under **Assets** in the Control Room and by `GET /api/v1/assets`
(JSON or `?format=csv`).

**Reported identity** comes from the devices themselves:

| Protocol | Source | Fields |
|----------|--------|--------|
| Modbus/TCP | Read Device Identification reply (fc 43 / MEI 14) | vendor, model (model name, else product name, else product code), firmware |
| EtherNet/IP | ListIdentity reply | vendor, model, firmware, serial, device type |
| BACnet/IP | I-Am | device instance, vendor id |

A new identity over the same protocol replaces the old one. If the model,
firmware or serial changed, `asset_changed` fires (on, high):
`Device 10.20.0.50 reported a new identity over EtherNet/IP: firmware 32.011 -> 33.011`.
An identity over a different protocol only fills fields that are still
empty and never alerts. `asset_changed` only uses `enabled` and `severity`.

**Role** is inferred from Modbus, S7, DNP3, EtherNet/IP, BACnet and IEC 104
traffic (MQTT and OPC UA are left out, since a broker or OPC UA server
answers requests without being a controller):

| Role | When |
|------|------|
| engineering_workstation | sent any control, program or diagnostic request |
| scada_server | sent requests to 3 or more devices |
| hmi | sent requests to fewer devices |
| controller | only answered requests, or announced itself with BACnet I-Am |

An operator can override it from the Assets page or with
`PUT /api/v1/assets/{mac}/role` (bearer token), choosing from those four
or `gateway`, `historian`, `other`. The override is saved with the device
straight away; an empty role goes back to inference.

## Flow baseline

Industrial networks are quiet on purpose: the same HMI polls the same PLCs
with the same operations all day. The flow baseline records every
(client, server, protocol, operation class) tuple from decoded requests.

- For the first `learning_hours` (default 168, one week) every tuple is
  stored as `learned`.
- After that, a tuple that is not in the baseline is stored as `new` and
  raises `baseline_new_flow` once:
  `New industrial flow 10.20.0.30 -> 10.20.0.60: S7comm program (not seen while learning)`.
- On the **Flow baseline** page (or the API) an operator approves new flows
  (`approved`), forgets them (the next matching request alerts again), or
  drops everything and starts learning again after a planned change.

The baseline is stored next to the device records and survives restarts:
the learning period does not start over when Cerberus restarts. Changing
`learning_hours` only affects the next relearn. At `max_flows` (default
10,000) further new tuples are counted in `dropped` and neither stored nor
alerted on; `cerberus_baseline_dropped_total` shows when that happens.

```yaml
flow_baseline:
  enabled: true
  learning_hours: 168
  severity: medium
  max_flows: 10000
```

API: `GET /api/v1/baseline` (`?status=new|learned|approved`, `?limit=`),
`POST /api/v1/baseline/approve` and `/forget` with `{"ids": [...]}`, and
`POST /api/v1/baseline/relearn`; the POSTs need the API token. Metrics:
`cerberus_baseline_flows{status}`, `cerberus_baseline_dropped_total`,
`cerberus_baseline_learning`.

## Zones and conduits

Zones and conduits describe how the site is meant to be segmented (IEC
62443). Each zone is a set of networks at one Purdue level; a conduit
allows traffic from one zone to another.

Set them up on the **Zones** page (unlock with the API token): add a zone
per network segment, then a conduit per expected connection, and adjust the
two zone alerts. Changes apply straight away, without a restart, and are
saved in Cerberus's database. They take precedence over the `segmentation`
section of the alerts file, which is used until something is saved from the
console; **Use the config file instead** discards the console changes. The
same is available over the API: `GET`, `PUT` (whole configuration) and
`DELETE` (back to the file) on `/api/v1/segmentation`.

The equivalent alerts file section:

```yaml
segmentation:
  zones:
    - {id: enterprise, name: Office LAN, level: 4, cidrs: [10.0.0.0/16]}
    - {id: dmz, name: Plant DMZ, level: 3, cidrs: [10.30.0.0/24]}
    - {id: supervisory, name: SCADA, level: 2, cidrs: [10.20.0.0/27]}
    - {id: control, name: Line 1 control, level: 1, cidrs: [10.20.0.0/24], industrial: true}
  conduits:
    - {from: supervisory, to: control, ports: [502, 102]}
    - {from: enterprise, to: dmz, ports: [443]}
    - {from: dmz, to: supervisory, bidirectional: true}
  no_conduit: {enabled: true, severity: medium, realert_seconds: 3600}
  level_skip: {enabled: true, severity: high, realert_seconds: 3600}
```

- An address belongs to the zone with the most specific matching prefix,
  so a `/27` for the SCADA servers can sit inside the `/24` control network.
- A conduit `from -> to` allows packets from `from` to the listed ports
  (any port when `ports` is empty) and the replies from those ports back.
  A TCP SYN from the `to` side is never treated as a reply.
  `bidirectional: true` lets either side open connections.
- Traffic between two different zones that no conduit allows raises
  `zone_no_conduit`, or `zone_level_skip` when the levels are more than one
  apart (enterprise straight to control):
  `No conduit for TCP 10.0.4.7:51000 -> 10.20.0.50:502 from Office LAN (level 4) to Line 1 control (level 1), skips 2 levels`.
  Alerts repeat at most once per `realert_seconds` for the same pair of
  addresses; `cerberus_zone_violations_total{from,to}` counts every packet.
- Traffic to or from an address outside every zone (the internet, an
  unlisted subnet) is not judged.
- **Watch-only**: zones with `industrial: true` default to `enforce: false`.
  A policy drop rule that overlaps one is refused unless the request sets
  `force` (see [active-response.md](active-response.md#safety-rails)). A
  dropped packet on a control network can stop a process; set
  `enforce: true` on a zone only when that is understood.

The **Zones** page draws the zones by Purdue level with their devices, and
lists the conduits and the zone pairs that saw traffic without one.
`GET /api/v1/zones` returns the same data. Each device carries its `zone`.

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

## PROFINET DCP

PROFINET runs directly on Ethernet, so the TC program handles it: frames
with ethertype 0x8892, untagged or behind one 802.1Q tag (PROFINET usually
travels with VLAN priority 6), become events when the frame id is a DCP id
(0xFEFC to 0xFEFF). Cyclic real-time frames, which carry process data every
few milliseconds, are left in the kernel and cost nothing. PROFINET frames
still count as "other" in the kernel counters.

Stations are named by MAC address, since DCP has no IP header; addresses in
alerts and the flow baseline are MACs. Identify responses and Hello
messages fill the device `asset` (type of station as the model, vendor from
the vendor id, the device id as the device type) and the station name goes
into `details`.

| Class | DCP |
|-------|-----|
| write | Set NameOfStation, Set IP parameters |
| control | Set control: reset to factory settings |
| other | Identify, Get, Hello, Set signal (flash the LED), transaction control |

| Rule | Fires on | Default |
|------|----------|---------|
| `profinet_write` | renaming a station or changing its address, which takes it off its controller | on, high |
| `profinet_control` | factory reset | on, high |

Example: `PROFINET DCP set_name from 02:00:00:00:00:01 to 02:00:00:00:00:09 (new name rogue)`

Because DCP has no IP, `allowed_sources` for these two rules takes MAC
addresses, for example the engineering laptop used for commissioning:
`allowed_sources: ["00:1b:1b:aa:bb:cc"]`. MAC addresses are accepted in
every industrial rule's allow-list; they only match Ethernet-only traffic.

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
