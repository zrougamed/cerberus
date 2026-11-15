# Control Room (web UI)

The **Control Room** is a React SPA (Vite + TypeScript + Tailwind + Chart.js)
built into `internal/api/web` and embedded in the binary with `go:embed`.
Navigation uses the URL **hash** (`HashRouter`) so the Go file server can keep
serving `/` for every client route.

## Source and build

| Path | Role |
|------|------|
| `web/` | React source |
| `internal/api/web/` | Production build output (committed for local/`make build`; embedded) |
| `make web` | `npm ci` + production build into `internal/api/web` |
| Dockerfile `ui` stage | Builds the SPA in Docker and overlays `internal/api/web` before the Go compile |

Dev: run the Go harness on `:18080`, then `npm run dev` in `web/` (Vite proxies `/api`).

## Global chrome

| Region | Elements |
|--------|----------|
| **Sidebar** | Cerberus shield+hex-mesh mark, grouped nav, build info, hide menu |
| **Top bar** | Page title, show menu, pause updates, theme toggle |
| **Dashboard** | Traffic counters, doughnut mix, packets sparkline, devices, anomaly teaser |
| **Analytics** | Chart.js bar/doughnut views for services, vendors, DNS |

## Route map

| Hash | Screen |
|------|--------|
| `#/` | Dashboard |
| `#/analytics` | Analytics charts |
| `#/devices` | Device table |
| `#/device/:mac` | Device detail, with industrial counters and reported identity |
| `#/zones` | Zones by Purdue level with their devices and traffic without a conduit; add, edit and remove zones and conduits and set the zone alerts (admin) |
| `#/assets` | Industrial asset inventory: role and protocol filters, CSV download, role override (analyst) |
| `#/alerts` | Rule alerts; analysts acknowledge them with an optional note |
| `#/anomalies` | Anomaly snapshot |
| `#/policy` | Active response |
| `#/captures` | Packet capture status, save the buffer now, download or delete pcapng files (admin) |
| `#/baseline` | Industrial flow baseline: learning state, new flows to approve or forget, known flows, relearn (approve and forget: analyst; relearn: admin) |
| `#/raw/:endpoint` | Raw JSON |

## Charts

Canvas Chart.js charts (CSP-friendly; no `unsafe-inline` styles required for drawing):

- Protocol doughnut
- Horizontal rank bars (services / vendors / DNS)
- Packets-per-refresh sparkline

## Accessibility and theming

- `data-theme="light"|"dark"` override; system preference otherwise
- Sidebar collapse in `sessionStorage`
- CSP: `script-src 'self'`; Google Fonts allowed for Barlow / IBM Plex Mono

## Related

- [api-reference.md](api-reference.md)
- [system-overview.md](system-overview.md)
