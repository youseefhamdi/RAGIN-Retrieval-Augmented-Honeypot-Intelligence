use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;
use futures::stream::{Stream, StreamExt};
use tracing::{info, warn, error, instrument};
use crate::{
    config::{GatewayConfig, ModelConfig, RoutingStrategy, SkillLevel},
    error::{GatewayError, GatewayResult},
    models::{
        ChatRequest, ChatResponse, ChatChunk, Message, CostInfo, ModelCatalog, CostEstimate,
    },
    clients::{LlmClient, ClientFactory},
    validation::ResponseValidator,
    metrics::MetricsCollector,
};
use uuid::Uuid;
use chrono::Utc;
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;

pub struct Gateway {
    config: Arc<GatewayConfig>,
    clients: Arc<DashMap<String, Arc<dyn LlmClient>>>,
    model_router: Arc<ModelRouter>,
    cost_tracker: Arc<CostTracker>,
    rate_limiter: Arc<RateLimiter>,
    circuit_breakers: Arc<DashMap<String, CircuitBreaker>>,
    response_cache: Arc<Mutex<LruCache<String, ChatResponse>>>,
    #[allow(dead_code)]
    validator: Arc<ResponseValidator>,
    metrics: Arc<MetricsCollector>,
    request_semaphore: Arc<Semaphore>,
}

pub struct GatewayBuilder {
    config: GatewayConfig,
}

impl GatewayBuilder {
    pub fn new(config: GatewayConfig) -> Self {
        Self { config }
    }

    pub async fn build(self) -> GatewayResult<Gateway> {
        let config = Arc::new(self.config);
        config.validate()?;

        let clients = Arc::new(DashMap::new());
        let factory = ClientFactory::new(config.clone());

        for (name, provider_config) in &config.providers {
            if provider_config.enabled {
                let client = factory.create_client(provider_config).await?;
                clients.insert(name.clone(), client);
                info!("Initialized provider: {}", name);
            }
        }

        let model_router = Arc::new(ModelRouter::new(config.clone()));
        let cost_tracker = Arc::new(CostTracker::new(config.clone()));
        let rate_limiter = Arc::new(RateLimiter::new(config.clone()));
        let circuit_breakers = Arc::new(DashMap::new());
        let response_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(config.caching.max_size_mb * 1024 / 100).unwrap_or(std::num::NonZeroUsize::new(5000).unwrap())
        )));
        let validator = Arc::new(ResponseValidator::new(config.clone())?);
        let metrics = Arc::new(MetricsCollector::new(config.clone())?);
        let request_semaphore = Arc::new(Semaphore::new(config.server.workers * 100));

        Ok(Gateway {
            config,
            clients,
            model_router,
            cost_tracker,
            rate_limiter,
            circuit_breakers,
            response_cache,
            validator,
            metrics,
            request_semaphore,
        })
    }
}

impl Gateway {
    #[instrument(skip(self, request), fields(model = %request.model, request_id))]
    pub async fn generate(&self, request: ChatRequest) -> GatewayResult<ChatResponse> {
        let request_id = Uuid::new_v4().to_string();
        tracing::Span::current().record("request_id", &request_id);

        let _permit = self.request_semaphore.acquire().await.map_err(|_| GatewayError::Internal("Semaphore closed".into()))?;

        let start = Instant::now();
        let model_name = request.model.clone();

        let model_config = self.config.models.get(&model_name)
            .ok_or_else(|| GatewayError::ModelNotFound { model: model_name.clone() })?;

        if !model_config.enabled {
            return Err(GatewayError::ModelNotFound { model: model_name });
        }

        self.rate_limiter.check_limits(&model_name).await?;

        let provider_name = self.model_router.select_provider(&model_name, &request).await?;
        let client = self.clients.get(&provider_name)
            .ok_or_else(|| GatewayError::NoAvailableProviders { model: model_name.clone() })?;

        let cb = self.circuit_breakers.entry(provider_name.clone()).or_insert_with(|| CircuitBreaker::new(self.config.circuit_breaker.clone()));
        if cb.is_open() {
            return Err(GatewayError::CircuitBreakerOpen { provider: provider_name });
        }

        let cache_key = self.compute_cache_key(&request);
        if self.config.caching.enabled && self.config.caching.cache_responses {
            if let Some(cached) = self.response_cache.lock().get(&cache_key) {
                self.metrics.record_cache_hit();
                return Ok(cached.clone());
            }
        }

        let mut last_error = None;
        for attempt in 0..=model_config.max_retries {
            if attempt > 0 {
                let backoff = Duration::from_millis(100 * 2_u64.pow(attempt - 1));
                tokio::time::sleep(backoff).await;
            }

            let request_timeout = Duration::from_secs(model_config.timeout_secs);
            let result = timeout(request_timeout, client.generate(request.clone())).await;

            match result {
                Ok(Ok(response)) => {
                    cb.record_success();
                    self.rate_limiter.record_request(&provider_name).await;

                    let cost = self.calculate_cost(&response, model_config);
                    self.cost_tracker.record_cost(&model_name, &provider_name, cost.clone()).await;

                    if self.config.caching.enabled && self.config.caching.cache_responses {
                        self.response_cache.lock().put(cache_key, response.clone());
                    }

                    self.metrics.record_request(&model_name, &provider_name, start.elapsed(), true, cost.total_cost_usd);
                    return Ok(response);
                }
                Ok(Err(e)) => {
                    cb.record_failure();
                    last_error = Some(e);
                    if !last_error.as_ref().unwrap().is_retryable() {
                        break;
                    }
                }
                Err(_) => {
                    cb.record_failure();
                    last_error = Some(GatewayError::Timeout { seconds: model_config.timeout_secs });
                }
            }
        }

        self.metrics.record_request(&model_name, &provider_name, start.elapsed(), false, 0.0);
        Err(last_error.unwrap_or_else(|| GatewayError::Internal("Max retries exceeded".into())))
    }

    #[instrument(skip(self, request), fields(model = %request.model, request_id))]
    pub async fn generate_stream(&self, request: ChatRequest) -> GatewayResult<std::pin::Pin<Box<dyn Stream<Item = GatewayResult<ChatChunk>> + Send + 'static>>> {
        let request_id = Uuid::new_v4().to_string();
        tracing::Span::current().record("request_id", &request_id);

        let _permit = self.request_semaphore.acquire().await.map_err(|_| GatewayError::Internal("Semaphore closed".into()))?;

        let model_name = request.model.clone();
        let model_config = self.config.models.get(&model_name)
            .ok_or_else(|| GatewayError::ModelNotFound { model: model_name.clone() })?;

        if !model_config.enabled {
            return Err(GatewayError::ModelNotFound { model: model_name });
        }

        self.rate_limiter.check_limits(&model_name).await?;

        let provider_name = self.model_router.select_provider(&model_name, &request).await?;
        let client = self.clients.get(&provider_name)
            .ok_or_else(|| GatewayError::NoAvailableProviders { model: model_name.clone() })?;

        {
            let cb = self.circuit_breakers.entry(provider_name.clone()).or_insert_with(|| CircuitBreaker::new(self.config.circuit_breaker.clone()));
            if cb.is_open() {
                return Err(GatewayError::CircuitBreakerOpen { provider: provider_name });
            }
        }

        let stream = client.generate_stream(request).await?;

        let cost_tracker = self.cost_tracker.clone();
        let rate_limiter = self.rate_limiter.clone();
        let provider = provider_name.clone();
        let model = model_name.clone();
        let circuit_breakers = self.circuit_breakers.clone();
        let provider_for_cb = provider_name.clone();

        let mapped_stream = stream.then(move |chunk_result| {
            let cost_tracker = cost_tracker.clone();
            let rate_limiter = rate_limiter.clone();
            let model = model.clone();
            let provider = provider.clone();
            let circuit_breakers = circuit_breakers.clone();
            let provider_for_cb = provider_for_cb.clone();
            async move {
                match chunk_result {
                    Ok(chunk) => {
                        if let Some(usage) = &chunk.usage {
                            let cost = CostInfo {
                                prompt_tokens: usage.prompt_tokens,
                                completion_tokens: usage.completion_tokens,
                                total_tokens: usage.total_tokens,
                                prompt_cost_usd: 0.0,
                                completion_cost_usd: 0.0,
                                total_cost_usd: 0.0,
                                model: model.clone(),
                                provider: provider.clone(),
                                timestamp: Utc::now(),
                            };
                            tokio::spawn(async move {
                                cost_tracker.record_cost(&model, &provider, cost).await;
                            });
                        }
                        rate_limiter.record_request(&provider_for_cb).await;
                        Ok(chunk)
                    }
                    Err(e) => {
                        if let Some(cb) = circuit_breakers.get(&provider_for_cb) {
                            cb.record_failure();
                        }
                        Err(e)
                    }
                }
            }
        });

        Ok(Box::pin(mapped_stream))
    }

    pub async fn get_models(&self) -> GatewayResult<ModelCatalog> {
        let entries: Vec<_> = self.clients.iter().map(|e| (e.key().clone(), e.value().clone())).collect();
        let mut all_models = Vec::new();
        for (_name, client) in &entries {
            match client.get_models().await {
                Ok(catalog) => all_models.extend(catalog.data),
                Err(e) => warn!("Failed to get models: {}", e),
            }
        }
        Ok(ModelCatalog { object: "list".to_string(), data: all_models })
    }

    pub async fn estimate_cost(&self, request: &ChatRequest) -> GatewayResult<CostEstimate> {
        let model_name = &request.model;
        let model_config = self.config.models.get(model_name)
            .ok_or_else(|| GatewayError::ModelNotFound { model: model_name.clone() })?;

        let prompt_tokens = self.estimate_tokens(&request.messages);
        let completion_tokens = request.max_tokens.unwrap_or(model_config.max_output_tokens as u32);

        let prompt_cost = (prompt_tokens as f64 / 1000.0) * model_config.input_cost_per_1k;
        let completion_cost = (completion_tokens as f64 / 1000.0) * model_config.output_cost_per_1k;

        Ok(CostEstimate {
            estimated_prompt_tokens: prompt_tokens,
            estimated_completion_tokens: completion_tokens,
            estimated_cost_usd: prompt_cost + completion_cost,
            model: model_name.clone(),
            provider: model_config.provider.clone(),
        })
    }

    fn compute_cache_key(&self, request: &ChatRequest) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        request.model.hash(&mut hasher);
        for msg in &request.messages {
            msg.role.hash(&mut hasher);
            if let Some(text) = msg.content.as_text() {
                text.hash(&mut hasher);
            }
        }
        
        
        format!("{:x}", hasher.finish())
    }

    fn estimate_tokens(&self, messages: &[Message]) -> u32 {
        messages.iter()
            .filter_map(|m| m.content.as_text())
            .map(|t| (t.len() / 4) as u32)
            .sum::<u32>()
            .max(1)
    }

    fn calculate_cost(&self, response: &ChatResponse, model_config: &ModelConfig) -> CostInfo {
        let usage = &response.usage;
        let prompt_cost = (usage.prompt_tokens as f64 / 1000.0) * model_config.input_cost_per_1k;
        let completion_cost = (usage.completion_tokens as f64 / 1000.0) * model_config.output_cost_per_1k;

        CostInfo {
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            total_tokens: usage.total_tokens,
            prompt_cost_usd: prompt_cost,
            completion_cost_usd: completion_cost,
            total_cost_usd: prompt_cost + completion_cost,
            model: response.model.clone(),
            provider: model_config.provider.clone(),
            timestamp: Utc::now(),
        }
    }

    pub async fn health_check(&self) -> HashMap<String, bool> {
        let entries: Vec<_> = self.clients.iter().map(|e| (e.key().clone(), e.value().clone())).collect();
        let mut results = HashMap::new();
        for (name, client) in &entries {
            results.insert(name.clone(), client.is_healthy().await);
        }
        results
    }

    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub fn metrics(&self) -> &MetricsCollector {
        &self.metrics
    }
}

struct ModelRouter {
    config: Arc<GatewayConfig>,
    latency_cache: Arc<DashMap<String, Duration>>,
}

impl ModelRouter {
    fn new(config: Arc<GatewayConfig>) -> Self {
        Self {
            config,
            latency_cache: Arc::new(DashMap::new()),
        }
    }

    async fn select_provider(&self, model_name: &str, request: &ChatRequest) -> GatewayResult<String> {
        let _model_config = self.config.models.get(model_name)
            .ok_or_else(|| GatewayError::ModelNotFound { model: model_name.to_string() })?;

        let mut available_providers: Vec<_> = self.config.providers.iter()
            .filter(|(_, p)| p.enabled && p.models.contains(&model_name.to_string()))
            .collect();

        if available_providers.is_empty() {
            return Err(GatewayError::NoAvailableProviders { model: model_name.to_string() });
        }

        match self.config.routing.strategy {
            RoutingStrategy::Priority => {
                available_providers.sort_by_key(|(_, p)| p.priority);
                Ok(available_providers[0].0.clone())
            }
            RoutingStrategy::CostOptimized => {
                available_providers.sort_by(|(_, a), (_, b)| {
                    let cost_a = self.config.models.get(&a.models[0]).map(|m| m.input_cost_per_1k + m.output_cost_per_1k).unwrap_or(f64::MAX);
                    let cost_b = self.config.models.get(&b.models[0]).map(|m| m.input_cost_per_1k + m.output_cost_per_1k).unwrap_or(f64::MAX);
                    cost_a.partial_cmp(&cost_b).unwrap_or(std::cmp::Ordering::Equal)
                });
                Ok(available_providers[0].0.clone())
            }
            RoutingStrategy::LatencyOptimized => {
                let mut best = &available_providers[0];
                let mut best_latency = Duration::MAX;
                for entry in &available_providers {
                    let name = &entry.0;
                    if let Some(latency) = self.latency_cache.get(name.as_str()) {
                        if *latency < best_latency {
                            best_latency = *latency;
                            best = entry;
                        }
                    }
                }
                Ok(best.0.clone())
            }
            RoutingStrategy::SkillBased => {
                if let Some(skill) = self.extract_skill_level(request) {
                    if let Some(model) = self.config.routing.skill_routing.get(&skill) {
                        if available_providers.iter().any(|(_, p)| p.models.contains(model)) {
                            for (name, p) in &available_providers {
                                if p.models.contains(model) {
                                    return Ok(name.to_string());
                                }
                            }
                        }
                    }
                }
                available_providers.sort_by_key(|(_, p)| p.priority);
                Ok(available_providers[0].0.clone())
            }
            RoutingStrategy::RoundRobin => {
                let idx = (chrono::Utc::now().timestamp_millis() as usize) % available_providers.len();
                Ok(available_providers[idx].0.clone())
            }
            RoutingStrategy::Weighted => {
                let total_weight: u32 = available_providers.iter().map(|(_, p)| 1000 / p.priority.max(1)).sum();
                let mut rng = rand::thread_rng();
                let target = rng.gen_range(0..total_weight);
                let mut current = 0;
                for (name, p) in &available_providers {
                    current += 1000 / p.priority.max(1);
                    if current > target {
                        return Ok(name.to_string());
                    }
                }
                Ok(available_providers[0].0.clone())
            }
        }
    }

    fn extract_skill_level(&self, request: &ChatRequest) -> Option<SkillLevel> {
        for msg in &request.messages {
            if msg.role == crate::models::Role::System {
                if let Some(text) = msg.content.as_text() {
                    if text.contains("Novice") { return Some(SkillLevel::Novice); }
                    if text.contains("Intermediate") { return Some(SkillLevel::Intermediate); }
                    if text.contains("Expert") { return Some(SkillLevel::Expert); }
                    if text.contains("APT") { return Some(SkillLevel::Apt); }
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn record_latency(&self, provider: &str, latency: Duration) {
        self.latency_cache.insert(provider.to_string(), latency);
    }
}

struct CostTracker {
    config: Arc<GatewayConfig>,
    daily_spend: Arc<RwLock<HashMap<String, f64>>>,
    monthly_spend: Arc<RwLock<HashMap<String, f64>>>,
    model_spend: Arc<DashMap<String, f64>>,
    provider_spend: Arc<DashMap<String, f64>>,
    #[allow(dead_code)]
    skill_spend: Arc<DashMap<SkillLevel, f64>>,
}

impl CostTracker {
    fn new(config: Arc<GatewayConfig>) -> Self {
        Self {
            config,
            daily_spend: Arc::new(RwLock::new(HashMap::new())),
            monthly_spend: Arc::new(RwLock::new(HashMap::new())),
            model_spend: Arc::new(DashMap::new()),
            provider_spend: Arc::new(DashMap::new()),
            skill_spend: Arc::new(DashMap::new()),
        }
    }

    async fn record_cost(&self, model: &str, provider: &str, cost: CostInfo) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let month = chrono::Utc::now().format("%Y-%m").to_string();

        {
            let mut daily = self.daily_spend.write().await;
            *daily.entry(today).or_insert(0.0) += cost.total_cost_usd;
        }
        {
            let mut monthly = self.monthly_spend.write().await;
            *monthly.entry(month).or_insert(0.0) += cost.total_cost_usd;
        }
        self.model_spend.entry(model.to_string()).and_modify(|v| *v += cost.total_cost_usd).or_insert(cost.total_cost_usd);
        self.provider_spend.entry(provider.to_string()).and_modify(|v| *v += cost.total_cost_usd).or_insert(cost.total_cost_usd);

        self.check_budget().await;
    }

    async fn check_budget(&self) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let month = chrono::Utc::now().format("%Y-%m").to_string();

        let daily = self.daily_spend.read().await.get(&today).copied().unwrap_or(0.0);
        let monthly = self.monthly_spend.read().await.get(&month).copied().unwrap_or(0.0);

        let config = &self.config.cost;
        if daily > config.daily_budget_usd * (f64::from(config.alert_threshold_percent) / 100.0) {
            warn!("Daily budget alert: ${:.2} / ${:.2}", daily, config.daily_budget_usd);
        }
        if monthly > config.monthly_budget_usd * (f64::from(config.alert_threshold_percent) / 100.0) {
            warn!("Monthly budget alert: ${:.2} / ${:.2}", monthly, config.monthly_budget_usd);
        }
        if daily > config.daily_budget_usd {
            error!("Daily budget exceeded: ${:.2} > ${:.2}", daily, config.daily_budget_usd);
        }
        if monthly > config.monthly_budget_usd {
            error!("Monthly budget exceeded: ${:.2} > ${:.2}", monthly, config.monthly_budget_usd);
        }
    }

    #[allow(dead_code)]
    pub async fn get_daily_spend(&self) -> f64 {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        self.daily_spend.read().await.get(&today).copied().unwrap_or(0.0)
    }

    #[allow(dead_code)]
    pub async fn get_monthly_spend(&self) -> f64 {
        let month = chrono::Utc::now().format("%Y-%m").to_string();
        self.monthly_spend.read().await.get(&month).copied().unwrap_or(0.0)
    }
}

struct RateLimiter {
    config: Arc<GatewayConfig>,
    global_requests: Arc<DashMap<String, u32>>,
    global_tokens: Arc<DashMap<String, u64>>,
    model_requests: Arc<DashMap<String, u32>>,
    model_tokens: Arc<DashMap<String, u64>>,
    client_requests: Arc<DashMap<String, u32>>,
    window_start: Arc<RwLock<chrono::DateTime<chrono::Utc>>>,
}

impl RateLimiter {
    fn new(config: Arc<GatewayConfig>) -> Self {
        Self {
            config,
            global_requests: Arc::new(DashMap::new()),
            global_tokens: Arc::new(DashMap::new()),
            model_requests: Arc::new(DashMap::new()),
            model_tokens: Arc::new(DashMap::new()),
            client_requests: Arc::new(DashMap::new()),
            window_start: Arc::new(RwLock::new(chrono::Utc::now())),
        }
    }

    async fn check_limits(&self, model: &str) -> GatewayResult<()> {
        self.reset_window_if_needed().await;

        let global_rpm = self.global_requests.get("global").map(|r| *r).unwrap_or(0);
        if global_rpm >= self.config.rate_limiting.global_rpm {
            return Err(GatewayError::RateLimit { provider: "global".into() });
        }

        let global_tpm = self.global_tokens.get("global").map(|r| *r).unwrap_or(0);
        if global_tpm >= self.config.rate_limiting.global_tpm {
            return Err(GatewayError::RateLimit { provider: "global".into() });
        }

        if let Some(&limit) = self.config.rate_limiting.per_model_rpm.get(model) {
            let current = self.model_requests.get(model).map(|r| *r).unwrap_or(0);
            if current >= limit {
                return Err(GatewayError::RateLimit { provider: format!("model:{}", model) });
            }
        }

        Ok(())
    }

    async fn record_request(&self, provider: &str) {
        self.global_requests.entry("global".to_string()).and_modify(|v| *v += 1).or_insert(1);
        self.model_requests.entry(provider.to_string()).and_modify(|v| *v += 1).or_insert(1);
    }

    async fn reset_window_if_needed(&self) {
        let mut window = self.window_start.write().await;
        let now = chrono::Utc::now();
        if now.signed_duration_since(*window).num_seconds() >= 60 {
            *window = now;
            self.global_requests.clear();
            self.global_tokens.clear();
            self.model_requests.clear();
            self.model_tokens.clear();
            self.client_requests.clear();
        }
    }
}

struct CircuitBreaker {
    config: crate::config::CircuitBreakerConfig,
    failures: Arc<Mutex<u32>>,
    successes: Arc<Mutex<u32>>,
    state: Arc<Mutex<CircuitState>>,
    last_failure: Arc<Mutex<Option<Instant>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    fn new(config: crate::config::CircuitBreakerConfig) -> Self {
        Self {
            config,
            failures: Arc::new(Mutex::new(0)),
            successes: Arc::new(Mutex::new(0)),
            state: Arc::new(Mutex::new(CircuitState::Closed)),
            last_failure: Arc::new(Mutex::new(None)),
        }
    }

    fn is_open(&self) -> bool {
        let mut state = self.state.lock();
        match *state {
            CircuitState::Open => {
                if let Some(last) = *self.last_failure.lock() {
                    if last.elapsed() > Duration::from_secs(self.config.timeout_secs) {
                        *state = CircuitState::HalfOpen;
                        *self.successes.lock() = 0;
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            }
            CircuitState::HalfOpen => false,
            CircuitState::Closed => false,
        }
    }

    fn record_success(&self) {
        let mut state = self.state.lock();
        match *state {
            CircuitState::HalfOpen => {
                *self.successes.lock() += 1;
                if *self.successes.lock() >= self.config.success_threshold {
                    *state = CircuitState::Closed;
                    *self.failures.lock() = 0;
                }
            }
            CircuitState::Closed => {
                *self.failures.lock() = 0;
            }
            _ => {}
        }
    }

    fn record_failure(&self) {
        let mut state = self.state.lock();
        *self.failures.lock() += 1;
        *self.last_failure.lock() = Some(Instant::now());

        match *state {
            CircuitState::Closed if *self.failures.lock() >= self.config.failure_threshold => {
                    *state = CircuitState::Open;
            }
            CircuitState::HalfOpen => {
                *state = CircuitState::Open;
            }
            _ => {}
        }
    }
}