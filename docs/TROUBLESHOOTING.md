# RAGIN Troubleshooting Guide

## Service Startup Issues

### Gateway fails to start

**Symptoms:** `gateway` container exits immediately, logs show config error

**Causes and fixes:**

| Cause | Log Indicator | Fix |
|-------|--------------|-----|
| Missing API key | `OPENROUTER_API_KEY not set` | Add key to `.env` file |
| Invalid config | `config validation failed` | Check `settings.yaml` syntax |
| Port conflict | `Address already in use` | Change `GATEWAY_PORT` in `.env` |
| Rust panic | `thread 'main' panicked` | Check Rust dependencies, rebuild |

```bash
# Debug
docker compose logs gateway --tail=50
docker compose run --rm gateway /bin/sh  # inspect image
```

### Python components fail to start

**Symptoms:** `chrollo`, `don`, or `hisoka` exits with error

```bash
# Check logs
docker compose logs chrollo --tail=50

# Common fixes
# 1. Import error → missing dependency
pip install -e ".[test]"  # rebuild image

# 2. Redis connection refused → Redis not ready
docker compose up -d redis
sleep 5
docker compose up -d chrollo

# 3. Model file missing
ls models/chrollo/rf_classifier.joblib  # must exist
```

---

## Runtime Issues

### Gateway 502 Errors

**Symptoms:** Nginx returns 502 for `/v1/` requests

**Diagnosis:**
```bash
# Check gateway health
curl http://localhost:8080/health

# Check circuit breaker state
curl http://localhost:9090/api/v1/query?query=ragin_circuit_breaker_state

# Check OpenRouter connectivity
docker compose exec gateway curl -s https://openrouter.ai/api/v1/models | head
```

**Fixes:**
1. OpenRouter down → Wait for recovery; gateway fallback chain should activate
2. Rate limited → Check rate limit config; increase `circuit_breaker_timeout_s`
3. Gateway OOM → Increase memory limit in `docker-compose.prod.yml`
4. Network issue → Check `ragin-internal` network; `docker network inspect ragin_ragin-internal`

### High Latency (>2s p99)

**Symptoms:** Alert fires for `HighLatencyP99`

**Diagnosis:**
```bash
# Check per-component latency
curl -s "http://localhost:9090/api/v1/query?query=histogram_quantile(0.99,sum(rate(ragin_http_request_duration_seconds_bucket[5m])) by (le,service))"

# Check memory usage
docker stats --no-stream
```

**Fixes:**
1. Don vector store pressure → Restart don; check FAISS index size
2. Gateway upstream latency → Check OpenRouter status; switch model
3. Redis slow → Check `redis-cli slowlog get 10`
4. Nginx buffer full → Increase `proxy_buffer_size`

### Session Leak

**Symptoms:** Redis memory growing, session count increasing

**Diagnosis:**
```bash
docker compose exec redis redis-cli INFO keyspace
docker compose exec redis redis-cli DBSIZE
```

**Fixes:**
1. Check TTL settings in `ragin/hisoka/session_manager.py`
2. Restart hisoka to clear in-memory state
3. Check `maxmemory-policy allkeys-lru` is set for Redis

### Cost Spike

**Symptoms:** `CostBudgetExceeded` alert fires

**Diagnosis:**
```bash
# Check total cost
curl -s "http://localhost:9090/api/v1/query?query=ragin_cost_total_usd"

# Per-component breakdown
curl -s "http://localhost:9090/api/v1/query?query=sum(rate(ragin_cost_usd_total[1h])) by (component)"

# Check for retry storms
docker compose logs gateway | grep -c retry
```

**Fixes:**
1. Model routing misconfigured → Verify `settings.yaml` routing rules
2. Retry storms → Check `max_retries: 3` is not exceeded
3. Expensive model for cheap tasks → Update routing to cheaper model
4. Temporary fix: Switch to local fallback

### Evasion Rate Spike

**Symptoms:** Many evasion detections in hisoka logs

**Diagnosis:**
```bash
docker compose logs hisoka | grep evasion | tail -20
```

**Investigation:**
1. Is an attacker fingerprinting the honeypot? → Check for repeated tool signatures
2. Is the evasion detector too sensitive? → Review patterns in `evasion_detector.py`
3. Adjust persona diversity if pattern is predictable

### Redis Issues

**Symptoms:** Connection refused, slow responses

```bash
# Check Redis status
docker compose exec redis redis-cli ping
docker compose exec redis redis-cli INFO memory
docker compose exec redis redis-cli INFO stats

# Clear stale data
docker compose exec redis redis-cli FLUSHDB

# Restart Redis
docker compose restart redis
```

---

## Monitoring Issues

### Prometheus not scraping targets

**Diagnosis:**
```bash
curl -s http://localhost:9090/api/v1/targets | python3 -m json.tool | grep -A5 '"health"'
```

**Fixes:**
1. Target shows `DOWN` → Check container health and port exposure
2. Network unreachable → Verify Docker network connectivity
3. Config error → Validate `prometheus.yml` syntax

### Grafana dashboards empty

**Fixes:**
1. Check Prometheus datasource configured: `/etc/grafana/provisioning/datasources/`
2. Check dashboard JSON valid: `/var/lib/grafana/dashboards/`
3. Restart Grafana: `docker compose restart grafana`

---

## Network Issues

### Cannot reach external services

```bash
# Test outbound connectivity from container
docker compose exec gateway curl -s https://openrouter.ai/api/v1/models > /dev/null && echo "OK"

# Check DNS resolution
docker compose exec gateway nslookup openrouter.ai

# Check network mode
docker network inspect ragin_ragin-internal
```

### Inter-component communication failures

```bash
# Test from one container to another
docker compose exec hisoka python3 -c "import urllib.request; print(urllib.request.urlopen('http://gateway:8080/health').read())"

# Check Docker DNS
docker compose exec hisoka nslookup gateway
```

---

## Log Analysis Patterns

### Quick health summary
```bash
for svc in gateway chrollo don hisoka; do
  echo "=== $svc ==="
  docker compose logs --since 1h $svc 2>&1 | grep -c ERROR || echo "0 errors"
done
```

### Find slow requests
```bash
docker compose logs --since 1h | grep -oP 'X-Response-Time: \K[0-9.]+s' | sort -rn | head
```

### Cost anomaly detection
```bash
# Requests costing more than $0.05
docker compose logs gateway | grep -oP 'cost_usd":\K[0-9.]+' | awk '$1 > 0.05 {print}'
```

---

## Recovery Procedures

### Full service restart (safe order)
```bash
docker compose down
docker compose up -d redis
sleep 5
docker compose up -d gateway
sleep 10
docker compose up -d chrollo don hisoka
sleep 5
docker compose up -d prometheus grafana nginx
```

### Individual component restart
```bash
docker compose restart <component>
# Wait for health check
watch -n 2 "docker compose ps"
```

### Force rebuild and restart
```bash
docker compose build --no-cache <component>
docker compose up -d --no-deps <component>
```
