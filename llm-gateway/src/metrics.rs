use prometheus::{Counter, Histogram, Gauge, Registry, Encoder, TextEncoder};
use std::sync::Arc;
use crate::{
    config::GatewayConfig,
    error::GatewayResult,
};

pub struct MetricsCollector {
    registry: Registry,
    requests_total: Counter,
    request_duration: Histogram,
    tokens_total: Counter,
    cost_total: Counter,
    active_requests: Gauge,
    cache_hits: Counter,
    cache_misses: Counter,
    errors_total: Counter,
    circuit_breaker_state: Gauge,
    rate_limit_rejections: Counter,
    budget_alerts: Counter,
}

impl MetricsCollector {
    pub fn new(_config: Arc<GatewayConfig>) -> GatewayResult<Self> {
        let registry = Registry::new();

        let requests_total = Counter::new("gateway_requests_total", "Total number of requests")?;
        let request_duration = Histogram::with_opts(prometheus::HistogramOpts::new(
            "gateway_request_duration_seconds",
            "Request duration in seconds"
        ).buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]))?;
        let tokens_total = Counter::new("gateway_tokens_total", "Total tokens processed")?;
        let cost_total = Counter::new("gateway_cost_usd_total", "Total cost in USD")?;
        let active_requests = Gauge::new("gateway_active_requests", "Currently active requests")?;
        let cache_hits = Counter::new("gateway_cache_hits_total", "Cache hits")?;
        let cache_misses = Counter::new("gateway_cache_misses_total", "Cache misses")?;
        let errors_total = Counter::new("gateway_errors_total", "Total errors")?;
        let circuit_breaker_state = Gauge::new("gateway_circuit_breaker_state", "Circuit breaker state (0=closed, 1=half-open, 2=open)")?;
        let rate_limit_rejections = Counter::new("gateway_rate_limit_rejections_total", "Rate limit rejections")?;
        let budget_alerts = Counter::new("gateway_budget_alerts_total", "Budget alerts")?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(request_duration.clone()))?;
        registry.register(Box::new(tokens_total.clone()))?;
        registry.register(Box::new(cost_total.clone()))?;
        registry.register(Box::new(active_requests.clone()))?;
        registry.register(Box::new(cache_hits.clone()))?;
        registry.register(Box::new(cache_misses.clone()))?;
        registry.register(Box::new(errors_total.clone()))?;
        registry.register(Box::new(circuit_breaker_state.clone()))?;
        registry.register(Box::new(rate_limit_rejections.clone()))?;
        registry.register(Box::new(budget_alerts.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            request_duration,
            tokens_total,
            cost_total,
            active_requests,
            cache_hits,
            cache_misses,
            errors_total,
            circuit_breaker_state,
            rate_limit_rejections,
            budget_alerts,
        })
    }

    pub fn record_request(&self, _model: &str, _provider: &str, duration: std::time::Duration, success: bool, cost_usd: f64) {
        self.requests_total.inc();
        self.request_duration.observe(duration.as_secs_f64());
        if success {
            self.tokens_total.inc();
            self.cost_total.inc_by(cost_usd);
        } else {
            self.errors_total.inc();
        }
    }

    pub fn record_tokens(&self, prompt: u64, completion: u64) {
        self.tokens_total.inc_by(prompt as f64 + completion as f64);
    }

    pub fn record_cost(&self, cost_usd: f64) {
        self.cost_total.inc_by(cost_usd);
    }

    pub fn inc_active(&self) {
        self.active_requests.inc();
    }

    pub fn dec_active(&self) {
        self.active_requests.dec();
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }

    pub fn record_error(&self, _error_type: &str) {
        self.errors_total.inc();
    }

    pub fn set_circuit_breaker_state(&self, _provider: &str, state: u8) {
        self.circuit_breaker_state.set(state as f64);
    }

    pub fn record_rate_limit_rejection(&self) {
        self.rate_limit_rejections.inc();
    }

    pub fn record_budget_alert(&self) {
        self.budget_alerts.inc();
    }

    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }

    pub fn export_prometheus(&self) -> String {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}