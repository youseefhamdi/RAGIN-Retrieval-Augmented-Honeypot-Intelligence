use std::sync::Arc;

pub mod config;
pub mod error;
pub mod models;
pub mod gateway;
pub mod validation;
pub mod prompt_engine;
pub mod clients;
pub mod metrics;

pub use error::{GatewayError, GatewayResult};
pub use config::{GatewayConfig, ModelConfig, ProviderConfig, SkillLevel};
pub use models::{ChatRequest, ChatResponse, ChatChunk, Message, Role, ModelInfo, ModelCatalog, CostInfo, CostEstimate, Usage};
pub use gateway::{Gateway, GatewayBuilder};
pub use validation::{ResponseValidator, ValidationResult};
pub use prompt_engine::{PromptEngine, PromptTemplate};

/// Re-export commonly used types
pub type ArcGateway = Arc<Gateway>;