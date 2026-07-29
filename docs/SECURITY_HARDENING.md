# RAGIN Security Hardening Guide

## Authentication & Authorization

### API Key Management

**Key Inventory:**

| Key | Purpose | Storage | Rotation |
|-----|---------|---------|----------|
| `OPENROUTER_API_KEY` | External LLM API | `.env` file (encrypted at rest) | 90 days |
| `API_KEY` | Inter-component auth | `.env` file | 30 days |
| `GRAFANA_ADMIN_PASSWORD` | Dashboard admin | `.env` file | 90 days |

**Rotation Procedure:**

1. Generate new key:
   ```bash
   openssl rand -hex 32  # for API_KEY
   ```
2. Update `.env` file
3. Update all services: `docker compose up -d --no-deps gateway chrollo don hisoka`
4. Verify connectivity with new key
5. Revoke old key at provider (OpenRouter dashboard)

**Storage Rules:**
- Never commit `.env` to version control
- Use Docker secrets for production: `docker secret create api_key ./secret.txt`
- Encrypt at rest with LUKS or cloud KMS
- Audit key access via Docker logs

### Gateway Auth Configuration

The Rust gateway validates `X-API-Key` headers on all non-health endpoints. The auth middleware in `server.py:56-62` enforces this for Python components.

```
# Configure in .env
API_KEY=<random-64-char-hex>
```

**Validation chain:**
```
Client → Nginx → X-API-Key header → Component auth middleware → Backend
```

### Component-to-Component Auth

All internal traffic stays on the `ragin-internal` Docker bridge network (not externally routable). For additional protection:

- Hisoka → Gateway: Uses `GATEWAY_URL` env var (no auth on internal network by design; network isolation is the control)
- Redis: No password by default in dev; set `requirepass` in production

```bash
# Production Redis auth
# Add to docker-compose.prod.yml redis command:
# --requirepass <redis-password>
```

---

## Network Security

### Docker Network Isolation

Two networks segment traffic:

```
┌─────────────────────────────────┐
│  ragin-internal (bridge,internal)│
│  All RAGIN components           │
│  NOT externally routable        │
└─────────────────────────────────┘
           │
┌──────────┴──────────────────────┐
│  ragin-external (bridge)         │
│  Nginx, Grafana only            │
│  Externally accessible          │
└─────────────────────────────────┘
```

**Only Nginx and Grafana** connect to both networks. All other services are isolated on `ragin-internal`.

### TLS/SSL Configuration

Nginx terminates TLS on port 443:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
```

**Certificate options:**
1. **Let's Encrypt** (recommended): `certbot certonly --standalone -d honeypot.yourdomain.com`
2. **Self-signed** (dev): `openssl req -x509 -nodes -days 365 -newkey rsa:2048 -out cert.pem -keyout key.pem`

Mount certificates to `/etc/nginx/ssl/` in the container.

### Firewall Rules

```bash
# Allow only necessary inbound
ufw default deny incoming
ufw allow 443/tcp    # HTTPS (attacker traffic)
ufw allow 3000/tcp   # Grafana (management only)
ufw allow 9090/tcp   # Prometheus (management only)
ufw deny 80/tcp      # Redirect to HTTPS, don't expose HTTP
ufw deny 6379/tcp    # Redis (internal only)
ufw deny 8080/tcp    # Gateway (internal only)
ufw deny 8081/tcp    # Chrollo (internal only)
ufw deny 8082/tcp    # Don (internal only)
ufw deny 8083/tcp    # Hisoka (internal only)
```

### VPN Access for Management

Management interfaces (Grafana, Prometheus) should only be accessible via VPN:

```bash
# WireGuard example: bind Grafana to VPN interface only
# In docker-compose.prod.yml:
# ports: "10.0.0.1:3000:3000"  # WireGuard IP only
```

---

## Application Security

### Input Validation Summary

All attacker-facing endpoints validate input through:

| Component | Validation | Max Size | Reject |
|-----------|-----------|----------|--------|
| Chrollo | Feature extraction bounds | 32KB payload | Empty/malformed JSON |
| Don | Query string sanitization | 32K tokens | SQL/XSS patterns in query |
| Hisoka | Response schema validation | 4K chars response | Prompt injection attempts |
| Gateway | Token count + timeout | 32K input / 8K output | Oversized payloads |

### Prompt Injection Protections

Hisoka and Don apply layered defenses against prompt injection:

1. **Input sanitization**: Strip control characters, normalize Unicode
2. **System prompt isolation**: Attacker input never touches system prompts directly
3. **Output validation**: Schema validation via `RESPONSE_VALIDATION` in `settings.yaml`
4. **Hallucination detection**: Self-consistency check with 3 samples and 0.8 threshold
5. **Safety filters**: Block categories include violence, malware creation, credential theft

### PII Handling

- RAGIN does not intentionally collect PII
- Attacker commands/logs are stored in Redis with TTL-based expiry
- Cost database (`data/costs.db`) contains only request metadata, no content
- Log rotation: 30-day retention (Prometheus), configurable per Docker logging driver

### Secret Management

| Secret | Dev | Production |
|--------|-----|------------|
| API keys | `.env` file | Docker secrets or cloud KMS |
| TLS certs | Self-signed in volume | Mounted from host or cert-manager |
| Redis password | None | Docker secret |
| Grafana admin | `.env` file | Docker secret |

```bash
# Create Docker secrets for production
echo -n "your-api-key" | docker secret create api_key -
echo -n "your-redis-password" | docker secret create redis_password -
echo -n "your-grafana-password" | docker secret create grafana_password -
```

---

## Compliance Considerations

### Data Retention Policies

| Data Type | Retention | Storage | Deletion |
|-----------|-----------|---------|----------|
| Session logs (Redis) | 24 hours default | Redis AOF | Automatic TTL |
| Prometheus metrics | 30 days | TSDB | Automatic rotation |
| Grafana dashboards | Indefinite | Volume | Manual cleanup |
| Cost records | 90 days | SQLite | Configurable in `settings.yaml` |
| Application logs | 7 days | Docker json-file | `max-file: 5` rotation |
| Alert history | 30 days | Prometheus | Automatic |

### Logging Requirements

All services log to stdout in JSON format:

```yaml
# settings.yaml OBSERVABILITY section
logging:
  level: "INFO"
  format: "json"
  output: "stdout"
```

**Required log fields:**
- Timestamp (ISO 8601)
- Service name
- Log level
- Message
- Request ID (for correlation)

### Audit Trail

- All API requests logged by Nginx with client IP, user agent, response status
- Prometheus tracks request counts, latency, error rates per component
- Cost database tracks per-request spending with model and component breakdown
- Evasion detection logs track attacker behavioral indicators

**Access controls on audit data:**
- Prometheus/Grafana: VPN-only access
- Redis: Internal network only
- Cost DB: File permissions 600
