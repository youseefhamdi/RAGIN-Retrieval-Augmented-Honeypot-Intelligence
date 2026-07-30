use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::{GatewayError, GatewayResult};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub providers: HashMap<String, ProviderConfig>,
    pub models: HashMap<String, ModelConfig>,
    pub routing: RoutingConfig,
    pub rate_limiting: RateLimitingConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub caching: CachingConfig,
    pub cost: CostConfig,
    pub validation: ValidationConfig,
    pub prompt_engine: PromptEngineConfig,
    pub metrics: MetricsConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub max_request_size: usize,
    pub request_timeout_secs: u64,
    pub keep_alive_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub provider_type: ProviderType,
    pub api_key: Option<String>,
    pub base_url: String,
    pub api_base_url: String,
    pub models: Vec<String>,
    pub priority: u32,
    pub enabled: bool,
    pub weight: u32,
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    OpenRouter,
    Ollama,
    OpenAI,
    Anthropic,
    Custom,
    Mock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub provider: String,
    pub context_window: usize,
    pub max_output_tokens: usize,
    pub input_cost_per_1k: f64,
    pub output_cost_per_1k: f64,
    pub capabilities: ModelCapabilities,
    pub skill_levels: Vec<SkillLevel>,
    pub enabled: bool,
    pub max_retries: u32,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelCapabilities {
    pub chat: bool,
    pub completion: bool,
    pub function_calling: bool,
    pub vision: bool,
    pub json_mode: bool,
    pub streaming: bool,
    pub system_prompt: bool,
    pub parallel_tool_calls: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SkillLevel {
    Novice,
    Intermediate,
    Expert,
    Apt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub strategy: RoutingStrategy,
    pub fallback_enabled: bool,
    pub fallback_models: Vec<String>,
    pub skill_routing: HashMap<SkillLevel, String>,
    pub latency_threshold_ms: u64,
    pub cost_threshold_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    Priority,
    CostOptimized,
    LatencyOptimized,
    SkillBased,
    RoundRobin,
    Weighted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub global_rpm: u32,
    pub global_tpm: u64,
    pub per_model_rpm: HashMap<String, u32>,
    pub per_client_rpm: HashMap<String, u32>,
    pub burst_allowance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachingConfig {
    pub enabled: bool,
    pub cache_responses: bool,
    pub cache_embeddings: bool,
    pub max_size_mb: usize,
    pub ttl_secs: u64,
    pub redis_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostConfig {
    pub daily_budget_usd: f64,
    pub monthly_budget_usd: f64,
    pub alert_threshold_percent: f32,
    pub track_per_model: bool,
    pub track_per_provider: bool,
    pub track_per_skill: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub enabled: bool,
    pub strict_mode: bool,
    pub max_tokens_per_response: u32,
    pub allowed_finish_reasons: Vec<String>,
    pub content_filters: Vec<ContentFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFilter {
    pub name: String,
    pub pattern: String,
    pub action: FilterAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    Block,
    Warn,
    Redact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptEngineConfig {
    pub templates_dir: String,
    pub default_skill_level: SkillLevel,
    pub auto_detect_skill: bool,
    pub max_context_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus_port: u16,
    pub log_level: String,
    pub sample_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub api_keys: HashMap<String, ApiKeyConfig>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub cors_origins: Vec<String>,
    pub rate_limit_by_api_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    pub name: String,
    pub roles: Vec<String>,
    pub rate_limit_rpm: Option<u32>,
    pub cost_limit_usd: Option<f64>,
    pub allowed_models: Option<Vec<String>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl GatewayConfig {
    pub fn load() -> GatewayResult<Self> {
        use figment::{Figment, providers::{Format, Toml, Env}};

        let mut config = Figment::new()
            .merge(Toml::file("config.toml"))
            .merge(Env::prefixed("RAGIN_"))
            .extract::<GatewayConfig>()
            .map_err(|e| GatewayError::Config(format!("Failed to load config: {}", e)))?;

        // Fallback: read api key from flat env vars (figment Env doesn't auto-nest)
        if let Ok(api_key) = std::env::var("TOKENROUTER_API_KEY")
            .or_else(|_| std::env::var("RAGIN_TOKENROUTER_API_KEY"))
        {
            if let Some(provider) = config.providers.get_mut("tokenrouter") {
                if provider.api_key.is_none() {
                    provider.api_key = Some(api_key);
                }
            }
        }

        Ok(config)
    }

    pub fn validate(&self) -> GatewayResult<()> {
        if self.providers.is_empty() {
            return Err(GatewayError::Config("No providers configured".into()));
        }
        if self.models.is_empty() {
            return Err(GatewayError::Config("No models configured".into()));
        }
        for (name, provider) in &self.providers {
            if provider.enabled && provider.api_key.is_none() && provider.provider_type != ProviderType::Ollama {
                return Err(GatewayError::Config(format!("Provider {} missing API key", name)));
            }
            for model in &provider.models {
                if !self.models.contains_key(model) {
                    return Err(GatewayError::Config(format!("Provider {} references unknown model {}", name, model)));
                }
            }
        }
        for (name, model) in &self.models {
            if !self.providers.contains_key(&model.provider) {
                return Err(GatewayError::Config(format!("Model {} references unknown provider {}", name, model.provider)));
            }
        }
        Ok(())
    }
}



impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 8080,
            workers: 4,
            max_request_size: 10 * 1024 * 1024,
            request_timeout_secs: 60,
            keep_alive_secs: 30,
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        let mut skill_routing = HashMap::new();
        skill_routing.insert(SkillLevel::Novice, "gpt-4o-mini".into());
        skill_routing.insert(SkillLevel::Intermediate, "gpt-4o".into());
        skill_routing.insert(SkillLevel::Expert, "claude-3-5-sonnet".into());
        skill_routing.insert(SkillLevel::Apt, "gpt-4-turbo".into());

        Self {
            strategy: RoutingStrategy::Priority,
            fallback_enabled: true,
            fallback_models: vec!["gpt-4o-mini".into()],
            skill_routing,
            latency_threshold_ms: 5000,
            cost_threshold_usd: 0.01,
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            global_rpm: 1000,
            global_tpm: 100000,
            per_model_rpm: HashMap::new(),
            per_client_rpm: HashMap::new(),
            burst_allowance: 1.5,
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout_secs: 30,
        }
    }
}

impl Default for CachingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_responses: true,
            cache_embeddings: false,
            max_size_mb: 100,
            ttl_secs: 3600,
            redis_url: None,
        }
    }
}

impl Default for CostConfig {
    fn default() -> Self {
        Self {
            daily_budget_usd: 100.0,
            monthly_budget_usd: 1000.0,
            alert_threshold_percent: 80.0,
            track_per_model: true,
            track_per_provider: true,
            track_per_skill: true,
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_mode: false,
            max_tokens_per_response: 8192,
            allowed_finish_reasons: vec!["stop".into(), "length".into(), "tool_calls".into(), "content_filter".into()],
            content_filters: vec![],
        }
    }
}

impl Default for PromptEngineConfig {
    fn default() -> Self {
        Self {
            templates_dir: "./templates".into(),
            default_skill_level: SkillLevel::Intermediate,
            auto_detect_skill: true,
            max_context_tokens: 128000,
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prometheus_port: 9090,
            log_level: "info".into(),
            sample_rate: 1.0,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            api_keys: HashMap::new(),
            tls_cert_path: None,
            tls_key_path: None,
            cors_origins: vec!["*".into()],
            rate_limit_by_api_key: true,
        }
    }
}