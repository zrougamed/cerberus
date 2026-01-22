# Cerberus Network Monitor UI

A modern, real-time network monitoring dashboard built with React, TypeScript, and Tailwind CSS. Designed as a containerized frontend that connects to the Cerberus network monitoring backend.

## Features

- **Dashboard**: Real-time overview with packet statistics, traffic charts, and live activity feed
- **Devices**: Browse and filter network devices with detailed connection information
- **Device Detail**: Deep-dive into individual device traffic, DNS queries, and connection patterns
- **Patterns**: Live stream of network communication events with protocol filtering
- **Interfaces**: Monitor status of network adapters
- **Lookup Tools**: MAC vendor and port service lookup utilities
- **Theme Toggle**: Light/dark mode support with system preference detection

## Tech Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS v4
- **Charts**: Recharts
- **State Management**: TanStack Query (React Query)
- **Routing**: Wouter
- **UI Components**: Radix UI / shadcn/ui
- **Theming**: next-themes
- **Container**: Docker with nginx

## Quick Start with Docker

### Using Make (Recommended)

```bash
# Build the image
make build

# Run with default settings (port 3000)
make run

# Run with custom backend and port
make run PORT=8080 CERBERUS_BACKEND=http://10.0.0.5:8080/api/v1/

# View logs
make logs

# Stop the container
make stop

# Build and push to a registry
make build IMAGE_TAG=v1.0.0
make push REGISTRY=ghcr.io/myorg IMAGE_TAG=v1.0.0

# See all available commands
make help
```

### Manual Docker Commands

```bash
# Build the Docker image
docker build -t cerberus-ui .

# Run with your Cerberus backend
docker run -d \
  -p 3000:80 \
  -e CERBERUS_BACKEND=http://your-cerberus-host:8080/api/v1/ \
  cerberus-ui
```

The UI will be available at `http://localhost:3000`.

### Using Docker Compose

The included `docker-compose.yml` runs both the UI and Cerberus backend:

```bash
# Using Make
make compose-up

# Or directly
docker-compose up -d
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CERBERUS_BACKEND` | Cerberus API URL (runtime) | `http://cerberus:8080/api/v1/` |

The nginx server proxies all requests to `/api/v1/*` to the Cerberus backend specified in `CERBERUS_BACKEND`.

## Development

### Prerequisites

- Node.js 20+ (use `nvm use` with the included `.nvmrc`)
- npm

### Running Locally

```bash
# Install dependencies
npm install

# Start development server (with API proxy to localhost:8080)
npm run dev

# Or with mock data (no backend required)
VITE_USE_MOCK=true npm run dev
```

The app will be available at `http://localhost:5000`.

### Available Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start Vite dev server with hot reload |
| `npm run build` | Build for production |
| `npm run preview` | Preview production build locally |
| `npm run check` | TypeScript type checking |
| `npm run generate:api` | Generate types from OpenAPI spec |

### Generating API Types

To auto-generate TypeScript types from the OpenAPI specification:

```bash
npm run generate:api
```

This creates `client/src/types/api.generated.ts` with type-safe API interfaces.

## Architecture

### API Flow

```
[Browser] --> [nginx:80] --> /api/v1/* --> [Cerberus Backend:8080]
                        --> /health    --> 200 OK (health check)
                        --> /* (static files)
```

The frontend makes all API calls to `/api/v1/*` which nginx proxies to the Cerberus backend. This allows runtime configuration of the backend URL without rebuilding the frontend.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/stats` | GET | Network statistics |
| `/api/v1/stats/history` | GET | Time-series traffic data |
| `/api/v1/devices` | GET | List all devices |
| `/api/v1/devices/{mac}` | GET | Device details |
| `/api/v1/devices/{mac}/dns` | GET | Device DNS queries |
| `/api/v1/devices/{mac}/services` | GET | Device services |
| `/api/v1/devices/{mac}/patterns` | GET | Device patterns |
| `/api/v1/patterns` | GET | All communication patterns |
| `/api/v1/patterns/stream` | GET (SSE) | Real-time pattern stream |
| `/api/v1/interfaces` | GET | Network interfaces |
| `/api/v1/lookup/vendor/{mac}` | GET | MAC vendor lookup |
| `/api/v1/lookup/service/{port}` | GET | Port service lookup |

## Project Structure

```
├── client/
│   ├── src/
│   │   ├── components/
│   │   │   ├── charts/        # Recharts visualizations
│   │   │   ├── common/        # Shared UI components (ErrorBoundary, ThemeToggle)
│   │   │   ├── dashboard/     # Dashboard-specific components
│   │   │   ├── layout/        # App shell (Sidebar, Header)
│   │   │   └── ui/            # shadcn/ui components
│   │   ├── lib/
│   │   │   ├── api.ts         # API client
│   │   │   ├── mockData.ts    # Mock data for development
│   │   │   └── utils.ts       # Utility functions
│   │   ├── pages/             # Route components
│   │   ├── types/             # TypeScript interfaces
│   │   └── App.tsx            # Main app with routing
│   └── index.html
├── .env.example               # Environment variable template
├── .nvmrc                     # Node.js version specification
├── Dockerfile                 # Multi-stage build
├── docker-entrypoint.sh       # Runtime config injection
├── nginx.conf                 # nginx with API proxy + health check
├── docker-compose.yml         # Full stack deployment
└── package.json
```

## Design

The UI follows a "Dark Future" aesthetic with:

- Deep slate backgrounds with electric blue accents
- Light and dark mode support via theme toggle
- Protocol-specific color coding:
  - **TCP**: Blue
  - **UDP**: Green
  - **ICMP**: Yellow
  - **DNS**: Purple
  - **HTTP**: Cyan
  - **TLS**: Pink
  - **ARP**: Orange
- JetBrains Mono for data/code display
- Glassmorphism cards with subtle neon glows
- Real-time data updates every 3-5 seconds
