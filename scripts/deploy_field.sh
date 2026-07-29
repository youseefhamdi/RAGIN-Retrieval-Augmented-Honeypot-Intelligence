#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RAGIN Field Deployment Script
# Deploys the full RAGIN stack on a fresh VPS for 3+ month data collection.
#
# Usage:
#   ./scripts/deploy_field.sh --domain honeypot.example.com --api-key sk-or-xxx
#
# Requirements:
#   - Fresh Ubuntu 22.04+ VPS with root access
#   - Domain pointing to the VPS IP (A record)
#   - OpenRouter API key
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOY_LOG="$ROOT/logs/deploy_field.log"
ENV_FILE="$ROOT/.env"
BACKUP_DIR="$ROOT/data/backups"

# ─── Defaults ────────────────────────────────────────────────────────────────
DOMAIN=""
API_KEY=""
GRAFANA_PASSWORD="$(openssl rand -base64 16 | tr -dc 'A-Za-z0-9' | head -c 16)"
DRY_RUN=false
SKIP_SSL=false
SKIP_FIREWALL=false
HEALTH_TIMEOUT=60

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${GREEN}[DEPLOY]${NC} $*" | tee -a "$DEPLOY_LOG"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "$DEPLOY_LOG"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$DEPLOY_LOG"; }
info() { echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$DEPLOY_LOG"; }

# ─── Arg Parse ───────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
RAGIN Field Deployment

Usage: $0 [OPTIONS]

Options:
  --domain DOMAIN          Domain name for the honeypot (required)
  --api-key KEY            OpenRouter API key (required)
  --grafana-password PASS  Grafana admin password (auto-generated if omitted)
  --dry-run                Show what would be done without executing
  --skip-ssl               Skip SSL certificate setup (for testing)
  --skip-firewall          Skip firewall configuration
  --health-timeout SECS    Seconds to wait for health checks (default: 60)
  -h, --help               Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)        DOMAIN="$2"; shift 2 ;;
        --api-key)       API_KEY="$2"; shift 2 ;;
        --grafana-password) GRAFANA_PASSWORD="$2"; shift 2 ;;
        --dry-run)       DRY_RUN=true; shift ;;
        --skip-ssl)      SKIP_SSL=true; shift ;;
        --skip-firewall) SKIP_FIREWALL=true; shift ;;
        --health-timeout) HEALTH_TIMEOUT="$2"; shift 2 ;;
        -h|--help)       usage ;;
        *) err "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { err "--domain is required"; usage; }
[[ -z "$API_KEY" ]] && { err "--api-key is required"; usage; }

# ─── Pre-flight ──────────────────────────────────────────────────────────────
preflight() {
    log "═══ Pre-flight checks ═══"

    # Root check
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (for firewall/SSL setup)"
        exit 1
    fi

    # Docker check
    if ! command -v docker &>/dev/null; then
        warn "Docker not found — installing..."
        if [[ "$DRY_RUN" == "false" ]]; then
            curl -fsSL https://get.docker.com | sh
            systemctl enable docker && systemctl start docker
        fi
    fi

    # Docker Compose check
    if ! docker compose version &>/dev/null; then
        warn "Docker Compose not found — installing..."
        if [[ "$DRY_RUN" == "false" ]]; then
            apt-get update && apt-get install -y docker-compose-plugin
        fi
    fi

    # Git check
    if ! command -v git &>/dev/null; then
        warn "Git not found — installing..."
        if [[ "$DRY_RUN" == "false" ]]; then
            apt-get update && apt-get install -y git
        fi
    fi

    # curl/wget check
    for cmd in curl wget; do
        if ! command -v $cmd &>/dev/null; then
            apt-get update && apt-get install -y $cmd
        fi
    done

    log "Pre-flight checks passed"
}

# ─── Write .env ──────────────────────────────────────────────────────────────
write_env() {
    log "═══ Writing .env ═══"

    cat > "$ENV_FILE" <<ENVEOF
# RAGIN Field Deployment — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
OPENROUTER_API_KEY=$API_KEY
API_KEY=ragin-field-$(openssl rand -hex 16)
GRAFANA_ADMIN_PASSWORD=$GRAFANA_PASSWORD

# Domain
DOMAIN=$DOMAIN

# Ports (exposed via nginx reverse proxy — not directly exposed)
GATEWAY_PORT=8080
CHROLLO_PORT=8081
DON_PORT=8082
HISOKA_PORT=8083
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000

# Redis
REDIS_PASSWORD=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 32)

# Logging
RAGIN_LOG_LEVEL=INFO
ENVEOF

    chmod 600 "$ENV_FILE"
    log ".env written (secrets redacted from log)"
}

# ─── Firewall ────────────────────────────────────────────────────────────────
configure_firewall() {
    if [[ "$SKIP_FIREWALL" == "true" ]]; then
        warn "Skipping firewall configuration"
        return
    fi

    log "═══ Configuring firewall (ufw) ═══"

    if ! command -v ufw &>/dev/null; then
        apt-get update && apt-get install -y ufw
    fi

    # Reset and set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # SSH
    ufw allow 22/tcp comment "SSH"

    # HTTP/HTTPS (nginx reverse proxy)
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"

    # Enable
    ufw --force enable
    log "Firewall configured: SSH(22), HTTP(80), HTTPS(443) only"
}

# ─── SSL Certificates ────────────────────────────────────────────────────────
setup_ssl() {
    if [[ "$SKIP_SSL" == "true" ]]; then
        warn "Skipping SSL setup — generating self-signed certs"
        mkdir -p "$ROOT/ragin/config/nginx/ssl"
        openssl req -x509 -nodes -days 365 \
            -newkey rsa:2048 \
            -keyout "$ROOT/ragin/config/nginx/ssl/key.pem" \
            -out "$ROOT/ragin/config/nginx/ssl/cert.pem" \
            -subj "/CN=$DOMAIN" 2>/dev/null
        return
    fi

    log "═══ Setting up SSL certificates ═══"

    # Install certbot
    if ! command -v certbot &>/dev/null; then
        apt-get update && apt-get install -y certbot
    fi

    # Get cert using standalone mode (stop nginx first if running)
    docker compose -f "$ROOT/docker-compose.yml" stop nginx 2>/dev/null || true

    certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "admin@$DOMAIN" \
        -d "$DOMAIN" \
        --preferred-challenges http

    # Copy certs to nginx config
    SSL_DIR="$ROOT/ragin/config/nginx/ssl"
    mkdir -p "$SSL_DIR"
    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/cert.pem"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SSL_DIR/key.pem"
    chmod 600 "$SSL_DIR/key.pem"

    # Set up auto-renewal
    cat > /etc/cron.d/certbot-ragin <<EOF
0 3 * * * root certbot renew --quiet --post-hook "docker compose -f $ROOT/docker-compose.yml restart nginx"
EOF

    log "SSL certificates installed for $DOMAIN"
}

# ─── Deploy Stack ────────────────────────────────────────────────────────────
deploy_stack() {
    log "═══ Deploying RAGIN stack ═══"

    cd "$ROOT"

    # Build images
    log "Building Docker images..."
    docker compose build --no-cache

    # Start services (order matters for health checks)
    log "Starting services..."
    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

    # Wait for health
    log "Waiting for health checks (timeout: ${HEALTH_TIMEOUT}s)..."
    local start=$(date +%s)

    declare -A PORTS=(
        [gateway]=8080
        [chrollo]=8081
        [don]=8082
        [hisoka]=8083
        [redis]=6379
        [prometheus]=9090
        [grafana]=3000
    )

    for svc in gateway chrollo don hisoka redis prometheus grafana; do
        local port=${PORTS[$svc]}
        local elapsed=$(($(date +%s) - start))
        local remaining=$((HEALTH_TIMEOUT - elapsed))

        if [[ $remaining -le 0 ]]; then
            err "Health check timeout reached"
            break
        fi

        info "Waiting for $svc (port $port)..."
        local ok=false
        for i in $(seq 1 $remaining); do
            if curl -sf "http://127.0.0.1:$port/health" -o /dev/null 2>/dev/null || \
               curl -sf "http://127.0.0.1:$port/api/health" -o /dev/null 2>/dev/null; then
                log "  ✓ $svc healthy"
                ok=true
                break
            fi
            sleep 1
        done

        if [[ "$ok" == "false" ]]; then
            warn "  ✗ $svc did not become healthy within timeout"
        fi
    done

    log "Stack deployment complete"
}

# ─── Backup Setup ────────────────────────────────────────────────────────────
setup_backups() {
    log "═══ Setting up automated backups ═══"

    mkdir -p "$BACKUP_DIR"

    # Daily backup cron job
    cat > /etc/cron.d/ragin-backup <<EOF
# RAGIN daily backup — 2:00 AM UTC
0 2 * * * root $SCRIPT_DIR/backup_field_data.py --output "$BACKUP_DIR" >> $ROOT/logs/backup.log 2>&1
EOF

    # Weekly cleanup — remove backups older than 90 days
    cat > /etc/cron.d/ragin-cleanup <<EOF
# RAGIN backup cleanup — Sunday 4:00 AM UTC
0 4 * * 0 root find "$BACKUP_DIR" -name "*.tar.gz" -mtime +90 -delete >> $ROOT/logs/cleanup.log 2>&1
EOF

    log "Automated backups configured (daily at 02:00 UTC, 90-day retention)"
}

# ─── Health Monitor (systemd) ────────────────────────────────────────────────
setup_monitoring() {
    log "═══ Setting up health monitoring ═══"

    # Create systemd service for continuous health checks
    cat > /etc/systemd/system/ragin-health.service <<EOF
[Unit]
Description=RAGIN Health Monitor
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=$SCRIPT_DIR/field_health_check.py --interval 60 --log-dir $ROOT/logs
Restart=always
RestartSec=30
StandardOutput=append:$ROOT/logs/health_monitor.log
StandardError=append:$ROOT/logs/health_monitor.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ragin-health
    systemctl start ragin-health

    log "Health monitor running (systemd: ragin-health.service)"
}

# ─── Deploy Summary ──────────────────────────────────────────────────────────
summary() {
    log ""
    log "══════════════════════════════════════════════════════════════"
    log " RAGIN Field Deployment Complete"
    log "══════════════════════════════════════════════════════════════"
    log ""
    log " Domain:    https://$DOMAIN"
    log " Gateway:   https://$DOMAIN/v1/"
    log " Chrollo:   https://$DOMAIN/api/classify"
    log " Don:       https://$DOMAIN/api/analyze"
    log " Hisoka:    https://$DOMAIN/api/deceive"
    log ""
    log " Grafana:   https://$DOMAIN:3000 (admin / $GRAFANA_PASSWORD)"
    log " Prometheus: http://127.0.0.1:9090 (internal only)"
    log ""
    log " Logs:      $ROOT/logs/"
    log " Backups:   $BACKUP_DIR/ (daily at 02:00 UTC)"
    log " Health:    systemctl status ragin-health"
    log ""
    log " Quick commands:"
    log "   docker compose -f $ROOT/docker-compose.yml ps"
    log "   $SCRIPT_DIR/field_health_check.py"
    log "   $SCRIPT_DIR/collect_field_data.py --days 7"
    log "   $SCRIPT_DIR/backup_field_data.py --output $BACKUP_DIR"
    log ""
    log "══════════════════════════════════════════════════════════════"
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    mkdir -p "$ROOT/logs"

    log "RAGIN Field Deployment — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    log "Target: $DOMAIN"

    if [[ "$DRY_RUN" == "true" ]]; then
        warn "DRY RUN — no changes will be made"
    fi

    preflight
    write_env
    configure_firewall
    setup_ssl
    deploy_stack
    setup_backups
    setup_monitoring
    summary
}

main "$@"
