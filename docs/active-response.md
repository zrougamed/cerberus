# Active response (policy)

Cerberus can block or count traffic in the kernel, not only observe it. The
model follows [bpfilter](https://github.com/facebook/bpfilter) sets: rules are
entries in BPF maps that the TC classifier looks up for every packet, and each
rule has its own packet and byte counter.

Two layers, both in the TC classifier and both checked for every packet:

1. **Filter rules**: an ordered chain like a bpfilter chain (below).
2. **Blocklist**: fast set lookups of device MACs and IP ranges, for long
   lists. Checked after the filter rules unless a rule allowed the packet.

## Filter rules

Rules are checked top to bottom. Every matcher set on a rule must match.

| Matcher | Field | bpfilter equivalent |
|---------|-------|---------------------|
| Interface | `interface` | `meta.iface` |
| IP version | `family`: `ipv4`, `ipv6` | `meta.l3_proto` |
| Protocol | `protocol`: `tcp`, `udp`, `icmp`, `icmpv6` or a number | `meta.l4_proto` |
| Source / destination address or range | `src`, `dst` (+ `src_not`, `dst_not`) | `ip4/ip6.snet`, `dnet`, `not` |
| Source device | `src_mac` | |
| Source / destination port or range | `src_port`, `dst_port` such as `22` or `1024-65535` (+ `_not`) | `meta.sport`, `meta.dport`, `range` |
| TCP flags | `tcp_flags_any`, `tcp_flags_all` | `tcp.flags any`, `all` |
| ICMP type / code | `icmp_type`, `icmp_code` | `icmp.type`, `icmp.code` |

Verdicts:

| Verdict | Console | Effect |
|---------|---------|--------|
| `accept` | Allow | Stop, let the packet through, and skip the blocklist (an exception). |
| `drop` | Block | Stop and drop when enforcing. In dry run it stops evaluation but the packet passes. |
| `continue` | Count only | Count (and log) and go on to the next rule. |

Every rule counts packets and bytes. With `log`, matching packets are sent
to user space (interface, protocol, addresses, ports, TCP flags or ICMP
type, MAC, size, outcome) and shown in **Live log** and
`GET /api/v1/policy/log`; `log_every_seconds` (default 1) limits a rule to
one entry per interval, like bpfilter's `log ... every 1s`.

Up to 64 rules. Changes are atomic: the kernel keeps two copies of the
chain and switches with one write. IPv6 extension headers are not walked,
and only the first fragment of an IPv4 packet carries ports.

Example: let the admin workstation reach SSH, block all other SSH, and log
each attempt:

```bash
curl -s -X POST -H "$H" localhost:8080/api/v1/policy/filters -d \
  '{"id":"admin-ssh","verdict":"accept","match":{"protocol":"tcp","src":"192.168.1.10","dst_port":"22"}}'
curl -s -X POST -H "$H" localhost:8080/api/v1/policy/filters -d \
  '{"id":"ssh-block","verdict":"drop","log":true,"force":true,"match":{"protocol":"tcp","dst_port":"22"}}'
```

## What a blocklist entry matches

| Rule | Matches | Kernel map |
|------|---------|------------|
| Device (MAC) | Every frame whose **source** MAC is the device, ARP included. Use it to quarantine a device. | `policy_mac` (hash) |
| IPv4 / IPv6 address or range | Packets whose source, destination or either address is in the prefix (`direction: src`, `dst`, `any`). | `policy_v4`, `policy_v6` (LPM trie) |
| Hostname (DNS / SNI) | Devices whose observed DNS names or TLS SNI match the hostname (`host_match`: `dns`, `sni`, or `any`). Supports `*.evil.com`. Userspace sync installs derived MAC quarantine rules. | derived `policy_mac` |

Actions:

- `drop`: drop matching packets when the policy is **enforcing**.
- `log`: count matching packets only, in every mode.

A packet that matches several rules is counted by each; it is dropped if any
matching rule is `drop` and the policy is enforcing. Everything else is handed
to the next TC program unchanged (`TCX_NEXT`), so Cerberus coexists with
Cilium and other TC users.

## Where enforcement applies

The classifier runs on TC **ingress** of the monitored interfaces
(`CERBERUS_INTERFACES`). So rules affect traffic arriving at this host:

- On an ordinary LAN host: traffic to this host from the listed sources.
- On the gateway / router: traffic from LAN devices passing through it.
  Typical uses are `direction: dst` on the LAN interface to stop devices
  reaching a range, or a MAC rule to quarantine a device.

A host that only sees mirrored traffic (SPAN port) can count but cannot block.

## Modes

| Mode | Effect |
|------|--------|
| `monitor` (default) | Dry run. Every rule counts matches; nothing is dropped. |
| `enforce` | `drop` rules drop matching packets. |

Start in `monitor`, check the counters on the Policy page or `/metrics`, then
switch to `enforce`.

## Safety rails

- Changes need the admin role: `CERBERUS_API_TOKEN` (16+ characters), an admin
  named token or an admin sign-in (see [access-control.md](access-control.md)).
  Without any of them the policy is read-only and nothing can be blocked from
  the network.
- A rule may not cover this host's own addresses, the default gateway or the
  gateway's MAC unless the request sets `force`. A filter **Block** with no
  source, destination or device at all also needs `force`, since it matches
  traffic from every host. `0.0.0.0/0`, `::/0` and
  broadcast/multicast MACs are always refused.
- Industrial zones are watch-only (see
  [industrial-protocols.md](industrial-protocols.md#zones-and-conduits)): a
  drop blocklist entry or a filter **Block** whose address overlaps a zone
  marked `industrial` (and not `enforce: true`) is refused without `force`.
  A negated side (`src_not` / `dst_not`) counts as overlapping unless its
  prefix contains the whole zone. Count rules are always allowed. The check
  runs when a rule is added; rules that existed before the zone was
  configured are kept.
- `ttl_seconds` makes a rule temporary; it is removed automatically.
- At most 64 filter rules and 1024 blocklist entries. An address cannot
  appear in two blocklist entries; ids are unique across both.
- Every change is recorded in the audit trail (who, from which address, what),
  shown on the Policy page and returned by `GET /api/v1/policy`.
- If a kernel update or a disk write fails, the change is rolled back.

## Where the policy is stored

`CERBERUS_POLICY_FILE`, default `<CERBERUS_DATA_DIR>/policy.json`, written
atomically with mode 0600. It is loaded at startup and pushed to the kernel
once the classifier is attached. A file that fails validation stops Cerberus
from starting, rather than silently dropping the policy. You can edit the file
while Cerberus is stopped:

```json
{
  "version": 1,
  "mode": "monitor",
  "rules": [
    { "id": "known-c2", "action": "drop", "cidr": "203.0.113.0/24", "direction": "dst",
      "comment": "Threat intel: C2 range", "created_at": "2026-11-14T12:00:00Z" }
  ]
}
```

## Console

Open **Policy** in the Control Room. Enter the API token once (kept in that
browser tab only), then add rules, remove them, or switch the mode. On a
device's page, **Quarantine this device** and **Block its IP address** prefill
the form.

## API

```bash
TOKEN=...   # CERBERUS_API_TOKEN
H="Authorization: Bearer $TOKEN"

curl -s localhost:8080/api/v1/policy | jq .

curl -s -X POST -H "$H" -H 'X-Cerberus-Actor: alice' localhost:8080/api/v1/policy/rules \
  -d '{"id":"known-c2","action":"drop","cidr":"203.0.113.0/24","direction":"dst","comment":"intel feed"}'

curl -s -X POST -H "$H" localhost:8080/api/v1/policy/rules \
  -d '{"action":"drop","mac":"3c:22:fb:10:aa:01","ttl_seconds":3600,"comment":"camera beaconing"}'

curl -s -X PUT -H "$H" localhost:8080/api/v1/policy/mode -d '{"mode":"enforce"}'

curl -s -X DELETE -H "$H" localhost:8080/api/v1/policy/rules/known-c2
```

Full request and response shapes: [api-reference.md](api-reference.md#policy).

## Kernel requirements

TCX (kernel 6.6+), which Cerberus already needs to attach, plus `bpf_loop`
(5.17+) for the filter chain.

## Alerts and metrics

- When a rule's counter grows, Cerberus raises a `policy:<id>` rule alert (at
  most once per 10 minutes per rule): **high** when packets were dropped,
  **medium** for a `drop` rule in monitor mode ("would have dropped"), **low**
  for `log` rules. These go through the notification sinks like other alerts.
- Filter rules raise `filter:<id>` alerts the same way.
- `/metrics`: `cerberus_policy_dropped_packets_total` counts enforced drops;
  `cerberus_filter_log_lost_total` counts log entries lost when the log
  buffer was full.

## Testing the kernel path

`internal/policy/bpf_test.go` loads the compiled object and runs crafted
frames through the classifier with `BPF_PROG_TEST_RUN` (nothing is attached to
an interface). It needs root:

```bash
make bpf && sudo -E go test -run BPF -v ./internal/policy   # blocklist and filter chain
```
