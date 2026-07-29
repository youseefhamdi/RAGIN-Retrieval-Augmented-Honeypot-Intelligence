# RAGIN Cost Optimization Guide

## Cost Model

### OpenRouter Pricing Tiers

Per-request cost depends on which model handles the task. Current assignments from `settings.yaml`:

| Component | Model | Input $/1M tokens | Output $/1M tokens | Typical Request Cost |
|-----------|-------|-------------------|---------------------|---------------------|
| Chrollo inference | qwen-2.5-72b | $0.80 | $1.60 | ~$0.005 |
| Don retrieval | llama-3.1-8b | $0.10 | $0.10 | ~$0.003 |
| Hisoka deception | qwen-32b | $0.50 | $1.00 | ~$0.02 |
| Hisoka skill profiling | llama-3.1-70b | $0.60 | $0.80 | ~$0.01 |
| Local fallback | qwen2.5-32b | $0.00 | $0.00 | $0.00 |

### Monthly Cost Projections

Based on average token usage per request (~2K input, ~1K output):

| Scale | Daily Requests | Daily Cost | Monthly Cost |
|-------|---------------|------------|--------------|
| Low (dev/test) | 50 | ~$0.50 | ~$15 |
| Medium (small deployment) | 500 | ~$5.00 | ~$150 |
| Production | 2,000 | ~$20.00 | ~$600 |
| High scale | 10,000 | ~$100.00 | ~$3,000 |

### Budget Configuration

```yaml
# settings.yaml COST_TRACKING section
budget:
  daily_usd: 100.0        # Hard daily cap
  monthly_usd: 2000.0     # Hard monthly cap
  per_request_usd: 0.10   # Max cost per single request
  per_component:           # Per-component daily caps
    chrollo: 10.0
    don: 50.0
    hisoka: 40.0
```

---

## Optimization Strategies

### 1. Model Tiering

Route simpler tasks to cheaper models:

| Task | Current Model | Optimized Model | Savings |
|------|--------------|-----------------|---------|
| Simple classification | qwen-2.5-72b | llama-3.1-8b | ~87% |
| Keyword retrieval | llama-3.1-8b | gemma-2-9b | ~0% (same tier) |
| Simple deception | qwen-32b | llama-3.1-8b | ~80% |

**Implementation:** Update routing rules in `settings.yaml`:

```yaml
routing_rules:
  chrollo_inference:
    model: "meta-llama/llama-3.1-8b-instruct"  # Downgrade for simple cases
    max_latency_ms: 100
    fallback: "qwen/qwen-2.5-72b-instruct"     # Upgrade if confidence < threshold
```

### 2. Response Caching

Cache repeated queries to avoid redundant LLM calls:

- **Gateway level**: Redis-backed response cache with SHA-256 content hashing
- **Don level**: FAISS vector cache for frequently retrieved documents
- **Chrollo level**: Feature computation cache for repeated behavioral patterns

**Cache hit rate targets:**
- Don retrieval: 40-60% (repeated threat intel queries)
- Chrollo classification: 20-30% (similar behavioral patterns)
- Hisoka: 10-20% (persona selection cache)

### 3. Prompt Optimization

Reduce token usage per request:

| Technique | Impact | Implementation |
|-----------|--------|----------------|
| Shorter system prompts | 15-30% token reduction | Compress templates in `ragin/prompt/templates/` |
| Few-shot pruning | 10-20% reduction | Limit to 3 examples (currently 5 max) |
| Response length limits | 20-40% reduction | `max_response_tokens: 4000` (already configured) |
| Context window trimming | 10-25% reduction | Only send relevant retrieved documents |

### 4. Batch Processing

When latency permits, batch multiple requests:

- Chrollo classification: Batch feature extraction for multiple sessions
- Don retrieval: Batch vector similarity searches
- Gateway: N/A (one LLM call per request by design)

### 5. Local Fallback Utilization

The `local/qwen2.5-32b` fallback has zero API cost:

```yaml
LOCAL_FALLBACK:
  enabled: true
  endpoint: "http://localhost:8000/v1"
  max_concurrent: 4
```

Use local fallback for:
- Development and testing
- Non-critical classification tasks
- When OpenRouter is rate-limited or down
- Cost spike mitigation (auto-switch when daily budget >80%)

---

## Monitoring & Alerts

### Cost Tracking Dashboard

Grafana dashboard "Cost Tracking" shows:

- Real-time daily spend vs budget
- Per-component cost breakdown
- Per-model cost distribution
- Cost per request trend
- Anomaly detection (spend >2x rolling average)

### Budget Alert Thresholds

```yaml
# Prometheus alert rules
alerts:
  daily_threshold_pct: 80    # Alert at 80% of daily budget
  monthly_threshold_pct: 75  # Alert at 75% of monthly budget
  per_request_threshold_pct: 90  # Alert if single request >90% of limit
```

**Alert routing:**
- Warning (80%): Slack webhook
- Critical (90%): PagerDuty / immediate notification
- Emergency (100%): Auto-switch to local fallback

### Anomaly Detection

Monitor for:
- Sudden cost spikes (>2x hourly average)
- Unusual model routing (expensive model for cheap tasks)
- Failed request storms (retry loops consuming budget)
- Per-component budget overruns

```bash
# Manual cost check
curl -s http://localhost:9090/api/v1/query?query=ragin_cost_total_usd | python3 -m json.tool

# Per-component breakdown
curl -s "http://localhost:9090/api/v1/query?query=sum(rate(ragin_cost_usd_total[1h])) by (component)"
```

### Monthly Review Checklist

- [ ] Compare actual spend vs projections
- [ ] Review model usage distribution
- [ ] Identify optimization opportunities (cache hit rates, model downgrades)
- [ ] Update budget limits if usage patterns changed
- [ ] Review and prune unused prompt templates (reduce token overhead)
- [ ] Verify alert thresholds are appropriate for current traffic
