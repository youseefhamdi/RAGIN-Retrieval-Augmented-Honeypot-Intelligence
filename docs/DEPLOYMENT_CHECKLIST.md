# RAGIN Deployment Checklist

## Pre-Deployment

- [ ] All 345 tests passing (`make test-all`)
- [ ] Docker images build successfully (`docker compose build`)
- [ ] Environment variables configured (`.env` created from `.env.example`)
- [ ] `OPENROUTER_API_KEY` valid and tested against OpenRouter API
- [ ] `API_KEY` generated with sufficient entropy (`openssl rand -hex 32`)
- [ ] `GRAFANA_ADMIN_PASSWORD` set (not default `changeme`)
- [ ] SSL certificates installed at `/etc/nginx/ssl/cert.pem` and `key.pem`
- [ ] Prometheus config validated (`ragin/config/prometheus.yml`)
- [ ] Alert rules configured (`ragin/config/alert_rules.yml`)
- [ ] Budget limits set in `settings.yaml` (`COST_TRACKING.budget`)
- [ ] Grafana dashboards provisioned (`ragin/config/grafana/dashboards/`)
- [ ] Network requirements verified (outbound 443, inbound 443)
- [ ] Hardware meets minimum requirements (8 CPU, 16GB RAM for prod)

## Deployment

- [ ] Redis started and healthy (`docker compose up -d redis`)
- [ ] Redis health check passing (`redis-cli ping` → PONG)
- [ ] Gateway started and healthy (`curl http://localhost:8080/health`)
- [ ] Gateway circuit breaker in closed state (no errors in logs)
- [ ] Chrollo started and healthy (`curl http://localhost:8081/health`)
- [ ] Don started and healthy (`curl http://localhost:8082/health`)
- [ ] Hisoka started and healthy (`curl http://localhost:8083/health`)
- [ ] Hisoka connected to gateway (`GATEWAY_URL` resolves)
- [ ] Prometheus started and healthy (`curl http://localhost:9090/-/healthy`)
- [ ] Prometheus scraping all targets (check `/api/v1/targets`)
- [ ] Grafana started and healthy (`curl http://localhost:3000/api/health`)
- [ ] Grafana dashboards showing data (login and verify)
- [ ] Nginx started and healthy (`curl http://localhost:80/nginx-health`)
- [ ] TLS termination working (`curl -k https://localhost/`)

## Post-Deployment

- [ ] Smoke test: classify (`curl -X POST https://localhost/api/classify -d '{"session_log":{}}'`)
- [ ] Smoke test: analyze (`curl -X POST https://localhost/api/analyze -d '{"query":"test"}'`)
- [ ] Smoke test: deceive (`curl -X POST https://localhost/api/deceive`)
- [ ] Latency within thresholds (p99 < 2s per alert rules)
- [ ] Error rate < 1% (check Prometheus `ragin_http_requests_total{status=~"5.."}`)
- [ ] Cost tracking operational (check Grafana Cost Tracking dashboard)
- [ ] Circuit breaker in closed state (no open breakers in Prometheus)
- [ ] Canary stage metrics comparing correctly (if canary deployed)
- [ ] Rollback tested and working (`docker compose down && docker compose up -d`)
- [ ] All containers restart on failure (`restart: unless-stopped`)
- [ ] Log rotation working (check `max-size` / `max-file` in prod config)
- [ ] Redis persistence working (AOF rewrite completes)

## Sign-Off

| Role | Name | Date | Approved |
|------|------|------|----------|
| Tech Lead | ____________ | ____________ | [ ] |
| Security | ____________ | ____________ | [ ] |
| Operations | ____________ | ____________ | [ ] |
