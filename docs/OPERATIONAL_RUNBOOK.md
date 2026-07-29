# RAGIN Operations Manual

## System Overview

RAGIN is a cyber deception platform that uses LLM-powered honeypots to engage, classify, and analyze attackers in real time.

### Architecture

```
                          ┌─────────────────────────────────────────────┐
                          │              Nginx (443/SSL)                │
                          │         Reverse Proxy + TLS Termination     │
                          └──────┬──────────┬──────────┬───────────────┘
                                 │          │          │
                    ┌────────────┘    ┌─────┘          └────────────┐
                    ▼                 ▼                              ▼
        ┌───────────────┐  ┌──────────────────┐  ┌──────────────────────┐
        │   /v1/ (LLM)  │  │  /api/classify   │  │  /api/analyze        │
        │   Gateway     │  │  Chrollo          │  │  Don                 │
        │   (Rust)      │  │  (Python)         │  │  (Python)            │
        └──────┬────────┘  └──────────────────┘  └──────────────────────┘
               │                                             │
               │                          ┌──────────────────┘
               │                          ▼
               │               ┌──────────────────────┐
               │               │  /api/deceive         │
               │               │  Hisoka (Python)      │
               │               └──────────────────────┘
               │
    ┌──────────┴──────────────────────────────┐
    │          Internal Network                │
    │  ┌───────┐  ┌───────────┐  ┌─────────┐ │
    │  │ Redis  │  │ Prometheus│  │ Grafana │ │
    │  └───────┘  └───────────┘  └─────────┘ │
    └─────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Port | Role |
|-----------|------|------|
| **Nginx** | 80/443 | TLS termination, reverse proxy, rate limiting |
| **Gateway** (Rust) | 8080 | OpenRouter API proxy, circuit breakers, model routing, cost tracking |
| **Chrollo** (Python) | 8081 | Random Forest behavioral classifier — attacker skill level assessment |
| **Don** (Python) | 8082 | Hybrid RAG engine (FAISS + BM25) — threat intelligence retrieval, MITRE mapping |
| **Hisoka** (Python) | 8083 | Adaptive deception — persona management, response generation, dwell tracking |
| **Redis** | 6379 | Session storage, cache, rate limiting state |
| **Prometheus** | 9090 | Metrics collection and alerting |
| **Grafana** | 3000 | Monitoring dashboards |

### Data Flow

```
Attacker Request → Nginx → Chrollo (classify skill level)
                                → Don (retrieve threat intel, map to MITRE)
                                → Hisoka (select persona, generate deceptive response)
                                → Gateway (route to LLM via OpenRouter)
                                → Response → Attacker
```

1. **Chrollo** receives raw attacker behavior and extracts features (tool signatures, command patterns, timing)
2. **Don** takes the classified input and performs hybrid RAG retrieval against threat intelligence corpus
3. **Hisoka** orchestrates persona selection, generates LLM-powered deceptive responses, and tracks engagement
4. **Gateway** handles all LLM API calls with circuit breakers, rate limiting, and cost tracking

---

## Prerequisites

### Docker Requirements

- Docker Engine >= 24.0
- Docker Compose >= 2.20
- Docker BuildKit enabled

### API Keys

| Key | Source | Purpose |
|-----|--------|---------|
| `OPENROUTER_API_KEY` | [openrouter.ai](https://openrouter.ai) | LLM API access |
| `API_KEY` | Self-generated | Internal component authentication |
| `GRAFANA_ADMIN_PASSWORD` | Self-generated | Grafana dashboard access |
| `COST_ALERT_WEBHOOK` | Slack/Discord webhook | Cost alert notifications |

### Minimum Hardware

| Environment | CPU | RAM | Disk | Notes |
|-------------|-----|-----|------|-------|
| Development | 4 cores | 8 GB | 20 GB | Local testing |
| Production | 8 cores | 16 GB | 50 GB SSD | Recommended for 100+ concurrent sessions |
| High Scale | 16 cores | 32 GB | 100 GB SSD | 500+ concurrent sessions |

### Network Requirements

- Outbound HTTPS (443) to `openrouter.ai`
- Inbound 443 for attacker-facing traffic
- Inbound 3000 for Grafana (restrict to management VPN)
- Inbound 9090 for Prometheus (restrict to management VPN)
- Internal bridge network between all RAGIN services

---

## Deployment Procedures

### 1. First-Time Deployment

```bash
# Clone and configure
git clone <repo-url> && cd RAGIN
cp .env.example .env
# Edit .env with real API keys and passwords

# Build images
docker compose build

# Start infrastructure first
docker compose up -d redis

# Start LLM gateway
docker compose up -d gateway

# Wait for gateway health, then start application services
docker compose up -d chrollo don hisoka

# Start monitoring and proxy
docker compose up -d prometheus grafana nginx

# Verify all services
docker compose ps
# All services should show "healthy" status

# Run smoke tests
curl -k https://localhost/chrollo/health
curl -k https://localhost/don/health
curl -k https://localhost/hisoka/health
curl -k https://localhost/gateway/health
```

### 2. Upgrading an Existing Deployment

```bash
# 1. Run test suite against current code
make test-all

# 2. Build new images without stopping (no downtime yet)
docker compose build

# 3. Rolling restart: infrastructure first, then application services
docker compose up -d --no-deps redis prometheus grafana
sleep 10
docker compose up -d --no-deps gateway
sleep 15
docker compose up -d --no-deps chrollo don hisoka
docker compose up -d --no-deps nginx

# 4. Verify
docker compose ps
curl -k https://localhost/chrollo/health
```

### 3. Rolling Back a Deployment

```bash
# Option A: Roll back to previous image tag
# Edit docker-compose.yml or use a pinned tag
docker compose down
git checkout HEAD~1
docker compose up -d --build

# Option B: Rebuild current code with fixes
git checkout <commit-hash>
docker compose build
docker compose up -d --no-deps chrollo don hisoka gateway
```

### 4. Scaling Components

```bash
# Scale Chrollo (classification workers)
docker compose up -d --scale chrollo=3

# Scale Don (RAG engine workers)
docker compose up -d --scale don=2

# Note: Hisoka requires shared session state via Redis, scaling
# requires ensuring session affinity in nginx config.
```

---

## Daily Operations

### Health Check Procedures

```bash
# Full system health check
for svc in gateway chrollo don hisoka; do
  echo -n "$svc: "
  curl -sf http://localhost:${svc_port}/health | python3 -m json.tool || echo "FAILED"
done

# Redis connectivity
docker compose exec redis redis-cli ping

# Prometheus targets
curl -s http://localhost:9090/api/v1/targets | python3 -m json.tool | grep health

# Grafana
curl -sf http://localhost:3000/api/health
```

### Log Review Checklist

| Check | Command | Frequency |
|-------|---------|-----------|
| Error rates | `docker compose logs --since 1h \| grep -i error` | Every 4 hours |
| Circuit breaker trips | `docker compose logs gateway \| grep circuit` | Every 4 hours |
| Cost alerts | Check Grafana cost dashboard | Daily |
| Slow requests | `docker compose logs \| grep latency` | Daily |
| Evasion detections | `docker compose logs hisoka \| grep evasion` | Daily |

### Cost Monitoring

- Check Grafana "Cost Tracking" dashboard daily
- Review daily spend against `$DAILY_BUDGET_USD` limit
- Investigate any request exceeding `$0.10` per-request cost
- Monthly review of model usage breakdown by component

### Certificate Renewal

- TLS certificates in `/etc/nginx/ssl/`
- If using Let's Encrypt: certbot auto-renewal via cron
- If self-signed: regenerate quarterly
- Test renewal: `openssl x509 -in cert.pem -noout -enddate`

---

## Troubleshooting

| Symptom | Likely Cause | Action |
|---------|-------------|--------|
| Gateway 502 | OpenRouter down or rate limited | Check circuit breaker state; switch to fallback model; check `settings.yaml` routing rules |
| High latency (>2s p99) | Vector store memory pressure or large FAISS index | Restart don; check FAISS index size; increase don memory limit |
| Session leak | Hisoka not cleaning up expired sessions | Check Redis TTL; restart hisoka; inspect `session_manager.py` TTL settings |
| Cost spike | Model routing misconfigured; no-cost-limit enforcement | Check `settings.yaml` cost_optimization; verify budget alerts; review per-component spend |
| Evasion rate spike | Attacker fingerprinting honeypot | Review evasion logs in hisoka; adjust persona diversity; check for predictable response patterns |
| Redis OOM | Session accumulation; missing TTL | Check `maxmemory-policy`; increase limit; clear stale sessions |
| Gateway timeout | OpenRouter latency spike | Increase `proxy_read_timeout`; check fallback chain; verify network connectivity |
| Prometheus not scraping | Target down or network unreachable | Check `prometheus.yml` targets; verify Docker network; check container health |
| Auth failures (401) | API_KEY mismatch between components | Verify `.env` API_KEY matches all service configs; check nginx header forwarding |
| Build failure | Dependency version conflict | Run `docker compose build --no-cache`; check `pyproject.toml` versions |

---

## Emergency Procedures

### 1. Full System Shutdown

```bash
# Graceful shutdown (order matters)
docker compose stop nginx
docker compose stop chrollo don hisoka
docker compose stop gateway
docker compose stop prometheus grafana
docker compose stop redis

# Or all at once (less safe for data)
docker compose down
```

### 2. Data Recovery

```bash
# Redis data (append-only file)
docker compose exec redis redis-cli BGREWRITEAOF
cp redis-data/appendonly.aof /backup/

# Prometheus data
cp -r prometheus-data/ /backup/prometheus-$(date +%Y%m%d)/

# Grafana data
cp -r grafana-data/ /backup/grafana-$(date +%Y%m%d)/

# Cost database
cp data/costs.db /backup/costs-$(date +%Y%m%d).db
```

### 3. Incident Response Checklist

1. **Contain**: Stop nginx to block attacker traffic (`docker compose stop nginx`)
2. **Preserve**: Export all logs (`docker compose logs > /var/log/ragin-incident-$(date +%s).log`)
3. **Investigate**: Review evasion detection logs for attacker TTPs
4. **Remediate**: Patch, rotate keys, update firewall rules
5. **Restore**: Restart services in dependency order (redis → gateway → chrollo/don/hisoka → nginx)
6. **Verify**: Run smoke tests and confirm all health checks pass
7. **Document**: Record incident timeline, actions taken, and lessons learned

### 4. Communication Templates

**Internal Alert:**
```
RAGIN Incident: [SEVERITY]
Time: [UTC]
Affected: [COMPONENT]
Impact: [DESCRIPTION]
Status: [INVESTIGATING/MITIGATING/RESOLVED]
Action: [NEXT STEPS]
```

**Escalation:**
```
RAGIN Escalation: [COMPONENT] down for [DURATION]
Current state: [DESCRIPTION]
Business impact: [EFFECT ON DECEPTION OPERATIONS]
Required: [ENGINEERING/SECURITY/OPS SUPPORT]
```
