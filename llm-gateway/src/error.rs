use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Model not found: {model}")]
    ModelNotFound { model: String },

    #[error("No available providers for model: {model}")]
    NoAvailableProviders { model: String },

    #[error("Provider error: {0}")]
    ProviderError(String),

    #[error("Rate limit exceeded for {provider}")]
    RateLimit { provider: String },

    #[error("Circuit breaker open for provider: {provider}")]
    CircuitBreakerOpen { provider: String },

    #[error("Request timeout after {seconds}s")]
    Timeout { seconds: u64 },

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Tera template error: {0}")]
    Tera(#[from] tera::Error),

    #[error("Prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Insufficient budget: {0}")]
    BudgetExceeded(String),

    #[error("Content policy violation: {0}")]
    ContentPolicy(String),

    #[error("Content filtered: {0}")]
    ContentFiltered(String),
}

impl GatewayError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            GatewayError::ProviderError(_)
                | GatewayError::RateLimit { .. }
                | GatewayError::Timeout { .. }
                | GatewayError::Http(_)
                | GatewayError::Internal(_)
        )
    }

    pub fn status_code(&self) -> reqwest::StatusCode {
        use reqwest::StatusCode;
        match self {
            GatewayError::ModelNotFound { .. } => StatusCode::NOT_FOUND,
            GatewayError::NoAvailableProviders { .. } => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::RateLimit { .. } => StatusCode::TOO_MANY_REQUESTS,
            GatewayError::CircuitBreakerOpen { .. } => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::Timeout { .. } => StatusCode::REQUEST_TIMEOUT,
            GatewayError::Validation(_) => StatusCode::BAD_REQUEST,
            GatewayError::Authentication(_) => StatusCode::UNAUTHORIZED,
            GatewayError::BudgetExceeded(_) => StatusCode::PAYMENT_REQUIRED,
            GatewayError::ContentPolicy(_) => StatusCode::FORBIDDEN,
            GatewayError::ContentFiltered(_) => StatusCode::FORBIDDEN,
            GatewayError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::TemplateNotFound(_) => StatusCode::NOT_FOUND,
            GatewayError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::Http(e) => e.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            GatewayError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::Tera(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::Prometheus(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::ProviderError(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

pub type GatewayResult<T> = Result<T, GatewayError>;