# Cerberus Control Room (React)

Vite + React + TypeScript + Tailwind CSS + Chart.js.

## Develop

```bash
# API/console without BPF (repo root)
go run .local/devserver/main.go /tmp/cerberus-dev

# SPA with hot reload (proxies /api to :18080)
cd web && npm install && npm run dev
```

## Ship into the binary

```bash
make web   # writes internal/api/web for go:embed
```

Commit the updated `internal/api/web` assets with the source change.
