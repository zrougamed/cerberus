# Active response (policy)

Cerberus can block or count traffic in the kernel, not only observe it. The
model follows [bpfilter](https://github.com/facebook/bpfilter) sets: rules are
entries in BPF maps that the TC classifier looks up for every packet, and each
rule has its own packet and byte counter.

## What a rule matches

| Rule | Matches | Kernel map |
|------|---------|------------|
| Device (MAC) | Every frame whose **source** MAC is the device, ARP included. Use it to quarantine a device. | `policy_mac` (hash) |
| IPv4 / IPv6 address or range | Packets whose source, destination or either address is in the prefix (`direction: src`, `dst`, `any`). | `policy_v4`, `policy_v6` (LPM trie) |

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

- Changes need `CERBERUS_API_TOKEN` (16+ characters). Without it the policy is
  read-only and nothing can be blocked from the network.
- A rule may not cover this host's own addresses, the default gateway or the
  gateway's MAC unless the request sets `force`. `0.0.0.0/0`, `::/0` and
  broadcast/multicast MACs are always refused.
- `ttl_seconds` makes a rule temporary; it is removed automatically.
- At most 1024 rules. A rule's address cannot appear in two rules.
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

## Alerts and metrics

- When a rule's counter grows, Cerberus raises a `policy:<id>` rule alert (at
  most once per 10 minutes per rule): **high** when packets were dropped,
  **medium** for a `drop` rule in monitor mode ("would have dropped"), **low**
  for `log` rules. These go through the notification sinks like other alerts.
- `/metrics`: `cerberus_policy_dropped_packets_total` counts enforced drops.

## Testing the kernel path

`internal/policy/bpf_test.go` loads the compiled object and runs crafted
frames through the classifier with `BPF_PROG_TEST_RUN` (nothing is attached to
an interface). It needs root:

```bash
make bpf && sudo -E go test -run BPF -v ./internal/policy
```
