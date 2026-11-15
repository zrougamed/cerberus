# Terminal console

`cerberus tui` shows what a running Cerberus sees, in a terminal. It reads the
REST API, so you can run it:

- on the sensor: `cerberus tui`
- inside the container: `docker exec -it cerberus ./cerberus tui`
- from another machine: `cerberus tui --addr https://sensor.plant.example`

It needs no root and no BPF access, and it changes nothing except what you
ask for: acknowledging alerts and approving or forgetting baseline flows,
when your role allows it.

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `--addr` | `$CERBERUS_HTTP_ADDR`, else `127.0.0.1:8080` | `host:port` or an `http(s)://` URL. A wildcard listen address such as `0.0.0.0:8080` means this machine. |
| `--token-file` | | File holding an API token. Without it, `$CERBERUS_API_TOKEN` is used. |
| `--ca-file` | system roots | CA certificate to trust when `--addr` is https |
| `--interval` | `2s` | Refresh interval, from 500ms to 1m |

The token is never taken from the command line, where other users could read
it in the process list. Without a token the console is read-only. It also
works when `protect_reads` is on, provided the token has at least the viewer
role. See [access-control.md](access-control.md).

Inside the official container `CERBERUS_API_TOKEN` is already set for the
server, so `docker exec` gets the admin role.

## Views

| Key | View | Shows |
|-----|------|-------|
| `1` | Overview | Packet rate chart for the last few minutes, per-protocol rates with sparklines, alerts in the last hour by severity, anomaly score, policy mode and kernel attachment, baseline state, capture buffer and drops, advisory bundle age, top services and vendors, latest alerts |
| `2` | Devices | All devices: IP, MAC, vendor, interface, connection counts, gateway, last seen. Enter opens a device: role, reported identity (vendor, model, firmware, serial), services, traffic types, DNS, TLS and HTTP names, industrial counters and peers per protocol, and matching advisories |
| `3` | Alerts | Rule alerts, newest first, with ATT&CK for ICS techniques and who acknowledged them. Enter shows the full alert and its capture id |
| `4` | Anomalies | Score chart, robust z-score, centroid distance, the last window's features, what changed, recent anomalies |
| `5` | Assets | Industrial inventory: vendor, model, firmware, role (`*` when set by an operator), protocols, advisory count and worst severity |
| `6` | Zones | Zones by Purdue level, conduits, and traffic between zones with no conduit |
| `7` | Baseline | Learning or enforcing, new flows first |
| `8` | Policy | Mode, block rules and filters with counters, recent changes |
| `9` | Captures | Buffer size, kernel drops, saved captures and whether each is complete |
| `0` | DNS/TLS | Query types, response codes, top domains, connections after a lookup, encrypted DNS, TLS versions, top server names |

## Keys

| Key | Action |
|-----|--------|
| `tab`, `←` `→` | Next or previous view |
| `↑` `↓`, `j` `k`, `PgUp` `PgDn`, `g` `G` | Move through a list |
| `enter`, `esc` | Open the selected device or alert; go back |
| `/` | Filter the list as you type; `esc` clears it |
| `s` | Change the sort column (Devices, Assets) |
| `a` | Acknowledge the selected alert, with an optional note (analyst) |
| `space`, `A`, `F` | Mark baseline flows, then approve or forget them after a y/n check (analyst) |
| `p`, `r` | Pause or resume updates; refresh now |
| `?`, `q` | Key help; quit |

Downloading captures and changing zones or policy stay in the Control Room
and the API, where the forms check what you enter.

## Small terminals

The console works at 80×24. Narrow tables hide less important columns first
(interface, gateway, HTTP and TLS counts on Devices; acknowledgement and
ATT&CK on Alerts), and the overview stacks its two columns. Colours follow
the terminal; set `NO_COLOR=1` to turn them off.

## Footprint

Each refresh reads only the endpoints the open view shows, plus the summary
and anomaly score for the charts. Chart history is a fixed buffer of 120
samples per series (four minutes at the default interval), and nothing is
written to disk. On the overview with a 2 s refresh it uses about 0.7% of one
core and 23 MB of memory.
