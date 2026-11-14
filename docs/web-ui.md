# Control Room (web UI)

The **Control Room** is a React SPA (Vite + TypeScript + Tailwind + Chart.js)
built into `internal/api/web` and embedded in the binary with `go:embed`.
Navigation uses the URL **hash** (`HashRouter`) so the Go file server can keep
serving `/` for every client route.

## Source and build

| Path | Role |
|------|------|
| `web/` | React source |
| `internal/api/web/` | Production build output (committed; embedded) |
| `make web` | `npm ci` + production build into `internal/api/web` |

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
| `#/device/:mac` | Device detail |
| `#/alerts` | Rule alerts |
| `#/anomalies` | Anomaly snapshot |
| `#/policy` | Active response |
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
