# CyberShield - Getting Started

## Quick Start (Docker)

```bash
# 1. Clone and navigate
cd feelFree

# 2. Copy environment file and add your keys
cp .env.example .env.local
# Edit .env.local: Add CLAUDE_API_KEY, API_KEYS

# 3. Build and run
make build
make up

# 4. Access
# API: http://localhost:8000
# Dashboard: http://localhost:8080
```

## Prerequisites

- Docker & Docker Compose
- Python 3.12+ (for local dev)
- Claude API key (for AI agents)

## Environment Setup

### Required Variables (.env.local)

```bash
# Generate an API key
python -c "import secrets; print(f'cs_{secrets.token_urlsafe(32)}')"

# Add to .env.local
API_KEYS=cs_your_generated_key_here
CLAUDE_API_KEY=sk-ant-your-claude-key
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `make build` | Build Docker images |
| `make up` | Start all services |
| `make down` | Stop all services |
| `make recycle` | Rebuild and restart (full refresh) |
| `make logs` | View all logs |
| `make status` | Check service status |
| `make health` | Test API health endpoint |

## Testing the API

```bash
# Health check (requires API key)
curl -H "X-API-Key: YOUR_KEY" http://localhost:8000/api/v1/health

# Or use Bearer token
curl -H "Authorization: Bearer YOUR_KEY" http://localhost:8000/api/v1/health
```

## Dashboard Access

1. Open http://localhost:8080
2. Enter your API key in the input field
3. Click "Connect"
4. View real-time threat monitoring

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   API       │────▶│   Agents    │────▶│    ML       │
│  :8000      │     │  (Claude)   │     │  Detection  │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │
       ▼                   ▼
┌─────────────┐     ┌─────────────┐
│  Dashboard  │     │   Redis     │
│   :8080     │     │   Cache     │
└─────────────┘     └─────────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| cybershield-api | 8000 | REST API |
| cybershield-dashboard | 8080 | Web UI |
| cybershield-agents | - | AI Agents |
| cybershield-ml | - | ML Detection |
| redis | 6379 | Cache |

## Troubleshooting

### Container won't start
```bash
make recycle  # Full rebuild
```

### API returns 401
```bash
# Check API key is set
docker-compose exec cybershield-api env | grep API_KEYS
```

### Dashboard disconnected
- Verify API key is correct
- Check dashboard logs: `make logs-dashboard`

## Local Development

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
make install-dev

# Run locally
make dev
```
