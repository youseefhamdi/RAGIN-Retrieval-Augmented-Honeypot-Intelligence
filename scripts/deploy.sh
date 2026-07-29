#!/usr/bin/env bash
set -euo pipefail

REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_PATH="${REMOTE_PATH:-/opt/ragin}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
PROD_FILE="${PROD_FILE:-docker-compose.prod.yml}"

if [ -z "$REMOTE_HOST" ]; then
  echo "ERROR: REMOTE_HOST not set"
  echo "Usage: REMOTE_HOST=your.vps.ip ./scripts/deploy.sh"
  exit 1
fi

echo "→ Syncing code to $REMOTE_HOST:$REMOTE_PATH"
rsync -az --delete \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.venv' \
  --exclude 'llm-gateway/target' \
  --exclude 'node_modules' \
  --exclude '.pytest_cache' \
  ./ "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH"

echo "→ Building and deploying on VPS"
ssh "$REMOTE_USER@$REMOTE_HOST" <<'SSH_EOF'
  set -euo pipefail
  cd /opt/ragin
  docker compose -f docker-compose.yml -f docker-compose.prod.yml build
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
  echo "→ Waiting for services..."
  sleep 5
  for svc in gateway chrollo don hisoka redis prometheus grafana; do
    if docker compose ps "$svc" --format json | grep -q '"Health":"healthy"'; then
      echo "  ✓ $svc"
    else
      echo "  ? $svc (check logs: docker compose logs $svc)"
    fi
  done
SSH_EOF

echo "→ Running smoke tests"
./scripts/smoke_test.sh "$REMOTE_HOST"
echo "✓ Deploy complete"
