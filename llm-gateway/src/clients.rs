use async_trait::async_trait;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use futures::stream::{Stream, StreamExt};
use crate::{
    config::{ProviderConfig, ProviderType},
    error::{GatewayError, GatewayResult},
    models::{
        ChatRequest, ChatResponse, ChatChunk, Choice, Delta, ModelInfo, ModelCatalog, Message, Usage, ChunkChoice,
    },
};

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn generate(&self, request: ChatRequest) -> GatewayResult<ChatResponse>;
    async fn generate_stream(&self, request: ChatRequest) -> GatewayResult<Pin<Box<dyn Stream<Item = GatewayResult<ChatChunk>> + Send + Unpin>>>;
    async fn get_models(&self) -> GatewayResult<ModelCatalog>;
    async fn is_healthy(&self) -> bool;
    fn provider_name(&self) -> &str;
}

pub struct OpenRouterClient {
    client: Client,
    config: ProviderConfig,
    base_url: String,
}

impl OpenRouterClient {
    pub fn new(config: ProviderConfig) -> GatewayResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        Ok(Self {
            client,
            base_url: config.api_base_url.clone(),
            config,
        })
    }

    fn build_request(&self, request: &ChatRequest) -> RequestBuilder {
        let mut rb = self.client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.config.api_key.as_deref().unwrap_or("")))
            .header("Content-Type", "application/json")
            .header("HTTP-Referer", "https://ragin.local")
            .header("X-Title", "RAGIN Gateway");

        for (key, value) in &self.config.headers {
            rb = rb.header(key, value);
        }

        rb.json(request)
    }

    #[allow(dead_code)]
    fn build_stream_request(&self, mut request: ChatRequest) -> RequestBuilder {
        request.stream = Some(true);
        self.build_request(&request)
    }
}

#[async_trait]
impl LlmClient for OpenRouterClient {
    async fn generate(&self, request: ChatRequest) -> GatewayResult<ChatResponse> {
        let response = self.build_request(&request).send().await?;
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GatewayError::ProviderError(format!(
                "{} - {} (code: {})",
                self.provider_name(),
                error_text,
                status.as_u16()
            )));
        }

        let chat_response: ChatResponse = response.json().await?;
        Ok(chat_response)
    }

    async fn generate_stream(&self, request: ChatRequest) -> GatewayResult<Pin<Box<dyn Stream<Item = GatewayResult<ChatChunk>> + Send + Unpin>>> {
        let _ = request;
        Ok(Box::pin(futures::stream::iter(vec![])))
    }

    async fn get_models(&self) -> GatewayResult<ModelCatalog> {
        let response = self.client
            .get(format!("{}/models", self.base_url))
            .header("Authorization", format!("Bearer {}", self.config.api_key.as_deref().unwrap_or("")))
            .send().await?;

        let catalog: ModelCatalog = response.json().await?;
        Ok(catalog)
    }

    async fn is_healthy(&self) -> bool {
        self.client
            .get(format!("{}/models", self.base_url))
            .header("Authorization", format!("Bearer {}", self.config.api_key.as_deref().unwrap_or("")))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    fn provider_name(&self) -> &str {
        &self.config.name
    }
}

pub struct OllamaClient {
    client: Client,
    config: ProviderConfig,
    base_url: String,
}

impl OllamaClient {
    pub fn new(config: ProviderConfig) -> GatewayResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        Ok(Self {
            client,
            base_url: config.api_base_url.clone(),
            config,
        })
    }

    fn build_request(&self, request: &ChatRequest) -> RequestBuilder {
        self.client
            .post(format!("{}/api/chat", self.base_url))
            .header("Content-Type", "application/json")
            .json(&OllamaChatRequest {
                model: request.model.clone(),
                messages: request.messages.iter().map(Into::into).collect(),
                stream: request.stream.unwrap_or(false),
                options: OllamaOptions {
                    temperature: request.temperature,
                    top_p: request.top_p,
                    num_predict: request.max_tokens.map(|v| v as i32),
                    stop: request.stop.clone(),
                },
            })
    }
}

#[derive(Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

impl From<&Message> for OllamaMessage {
    fn from(msg: &Message) -> Self {
        Self {
            role: format!("{:?}", msg.role).to_lowercase(),
            content: msg.effective_content().unwrap_or_default(),
        }
    }
}

#[derive(Serialize, Default)]
struct OllamaOptions {
    temperature: Option<f32>,
    top_p: Option<f32>,
    num_predict: Option<i32>,
    stop: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct OllamaChatResponse {
    model: String,
    created_at: String,
    message: OllamaMessage,
    done: bool,
    total_duration: Option<u64>,
    load_duration: Option<u64>,
    prompt_eval_count: Option<u32>,
    prompt_eval_duration: Option<u64>,
    eval_count: Option<u32>,
    eval_duration: Option<u64>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct OllamaStreamResponse {
    model: String,
    created_at: String,
    message: OllamaMessage,
    done: bool,
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn generate(&self, request: ChatRequest) -> GatewayResult<ChatResponse> {
        let response = self.build_request(&request).send().await?;
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GatewayError::ProviderError(format!(
                "{} - {} (code: {})",
                self.provider_name(),
                error_text,
                status.as_u16()
            )));
        }

        let ollama_resp: OllamaChatResponse = response.json().await?;

        let usage = Usage {
            prompt_tokens: ollama_resp.prompt_eval_count.unwrap_or(0),
            completion_tokens: ollama_resp.eval_count.unwrap_or(0),
            total_tokens: ollama_resp.prompt_eval_count.unwrap_or(0) + ollama_resp.eval_count.unwrap_or(0),
            prompt_tokens_details: None,
            completion_tokens_details: None,
        };

        Ok(ChatResponse {
            id: uuid::Uuid::new_v4().to_string(),
            object: "chat.completion".to_string(),
            created: chrono::Utc::now().timestamp() as u64,
            model: ollama_resp.model,
            choices: vec![Choice {
                index: 0,
                message: Message::assistant(ollama_resp.message.content),
                finish_reason: if ollama_resp.done { Some("stop".to_string()) } else { None },
                logprobs: None,
            }],
            usage,
            system_fingerprint: None,
        })
    }

    async fn generate_stream(&self, request: ChatRequest) -> GatewayResult<Pin<Box<dyn Stream<Item = GatewayResult<ChatChunk>> + Send + Unpin>>> {
        let mut request = request;
        request.stream = Some(true);

        let response = self.build_request(&request).send().await?;
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(GatewayError::ProviderError(format!(
                "{} - {} (code: {})",
                self.provider_name(),
                error_text,
                status.as_u16()
            )));
        }

        let stream = response.bytes_stream()
            .map(|chunk_result| {
                let bytes = match chunk_result {
                    Ok(b) => b,
                    Err(e) => return Some(Err(GatewayError::from(e))),
                };
                let text = String::from_utf8_lossy(&bytes);
                for line in text.lines() {
                    if line.trim().is_empty() { continue; }
                    if let Ok(ollama_chunk) = serde_json::from_str::<OllamaStreamResponse>(line) {
                        let chunk = ChatChunk {
                            id: uuid::Uuid::new_v4().to_string(),
                            object: "chat.completion.chunk".to_string(),
                            created: chrono::Utc::now().timestamp() as u64,
                            model: ollama_chunk.model,
                            choices: vec![ChunkChoice {
                                index: 0,
                                delta: Delta {
                                    role: None,
                                    content: Some(ollama_chunk.message.content),
                                    tool_calls: None,
                                },
                                finish_reason: if ollama_chunk.done { Some("stop".to_string()) } else { None },
                            }],
                            usage: if ollama_chunk.done { Some(Usage {
                                prompt_tokens: 0,
                                completion_tokens: 0,
                                total_tokens: 0,
                                prompt_tokens_details: None,
                                completion_tokens_details: None,
                            }) } else { None },
                        };
                        return Some(Ok(chunk));
                    }
                }
                None
            })
            .filter_map(futures::future::ready);

        Ok(Box::pin(stream))
    }

    async fn get_models(&self) -> GatewayResult<ModelCatalog> {
        let response = self.client
            .get(format!("{}/api/tags", self.base_url))
            .send().await?;

        #[derive(Deserialize)]
        struct OllamaModelsResponse {
            models: Vec<OllamaModel>,
        }

        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OllamaModel {
            name: String,
            size: u64,
            digest: String,
            details: OllamaModelDetails,
        }

        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OllamaModelDetails {
            format: String,
            family: String,
            families: Vec<String>,
            parameter_size: String,
            quantization_level: String,
        }

        let resp: OllamaModelsResponse = response.json().await?;
        let models: Vec<ModelInfo> = resp.models.into_iter().map(|m| ModelInfo {
            id: m.name.clone(),
            object: "model".to_string(),
            created: chrono::Utc::now().timestamp() as u64,
            owned_by: "ollama".to_string(),
            permission: vec![],
            root: None,
            parent: None,
            context_window: 4096,
            max_output_tokens: 2048,
            input_cost_per_1k: 0.0,
            output_cost_per_1k: 0.0,
            capabilities: crate::models::ModelCapabilities::default(),
            skill_levels: vec![],
            enabled: true,
        }).collect();

        Ok(ModelCatalog { object: "list".to_string(), data: models })
    }

    async fn is_healthy(&self) -> bool {
        self.client
            .get(format!("{}/api/tags", self.base_url))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    fn provider_name(&self) -> &str {
        &self.config.name
    }
}

pub struct MockClient {
    config: ProviderConfig,
    responses: Arc<Mutex<Vec<ChatResponse>>>,
    healthy: bool,
}

impl MockClient {
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            config,
            responses: Arc::new(Mutex::new(vec![])),
            healthy: true,
        }
    }

    pub async fn add_response(&self, response: ChatResponse) {
        self.responses.lock().await.push(response);
    }

    pub fn set_healthy(&mut self, healthy: bool) {
        self.healthy = healthy;
    }
}

#[async_trait]
impl LlmClient for MockClient {
    async fn generate(&self, request: ChatRequest) -> GatewayResult<ChatResponse> {
        let mut responses = self.responses.lock().await;
        if let Some(response) = responses.pop() {
            Ok(response)
        } else {
            Ok(ChatResponse {
                id: uuid::Uuid::new_v4().to_string(),
                object: "chat.completion".to_string(),
                created: chrono::Utc::now().timestamp() as u64,
                model: request.model,
                choices: vec![Choice {
                    index: 0,
                    message: Message::assistant("Mock response"),
                    finish_reason: Some("stop".to_string()),
                    logprobs: None,
                }],
                usage: Usage {
                    prompt_tokens: 10,
                    completion_tokens: 10,
                    total_tokens: 20,
                    prompt_tokens_details: None,
                    completion_tokens_details: None,
                },
                system_fingerprint: None,
            })
        }
    }

    async fn generate_stream(&self, request: ChatRequest) -> GatewayResult<Pin<Box<dyn Stream<Item = GatewayResult<ChatChunk>> + Send + Unpin>>> {
        let model = request.model.clone();
        let stream = futures::stream::iter(vec![
            Ok(ChatChunk {
                id: uuid::Uuid::new_v4().to_string(),
                object: "chat.completion.chunk".to_string(),
                created: chrono::Utc::now().timestamp() as u64,
                model: model.clone(),
                choices: vec![ChunkChoice {
                    index: 0,
                    delta: Delta {
                        role: Some(crate::models::Role::Assistant),
                        content: Some("Mock ".to_string()),
                        tool_calls: None,
                    },
                    finish_reason: None,
                }],
                usage: None,
            }),
            Ok(ChatChunk {
                id: uuid::Uuid::new_v4().to_string(),
                object: "chat.completion.chunk".to_string(),
                created: chrono::Utc::now().timestamp() as u64,
                model: model.clone(),
                choices: vec![ChunkChoice {
                    index: 0,
                    delta: Delta {
                        role: None,
                        content: Some("streaming ".to_string()),
                        tool_calls: None,
                    },
                    finish_reason: None,
                }],
                usage: None,
            }),
            Ok(ChatChunk {
                id: uuid::Uuid::new_v4().to_string(),
                object: "chat.completion.chunk".to_string(),
                created: chrono::Utc::now().timestamp() as u64,
                model: model.clone(),
                choices: vec![ChunkChoice {
                    index: 0,
                    delta: Delta {
                        role: None,
                        content: Some("response".to_string()),
                        tool_calls: None,
                    },
                    finish_reason: Some("stop".to_string()),
                }],
                usage: Some(Usage {
                    prompt_tokens: 10,
                    completion_tokens: 10,
                    total_tokens: 20,
                    prompt_tokens_details: None,
                    completion_tokens_details: None,
                }),
            }),
        ]);
        Ok(Box::pin(stream))
    }

    async fn get_models(&self) -> GatewayResult<ModelCatalog> {
        Ok(ModelCatalog {
            object: "list".to_string(),
            data: vec![ModelInfo {
                id: "mock-model".to_string(),
                object: "model".to_string(),
                created: chrono::Utc::now().timestamp() as u64,
                owned_by: "mock".to_string(),
                permission: vec![],
                root: None,
                parent: None,
                context_window: 4096,
                max_output_tokens: 2048,
                input_cost_per_1k: 0.0,
                output_cost_per_1k: 0.0,
                capabilities: crate::models::ModelCapabilities::default(),
                skill_levels: vec![],
                enabled: true,
            }],
        })
    }

    async fn is_healthy(&self) -> bool {
        self.healthy
    }

    fn provider_name(&self) -> &str {
        &self.config.name
    }
}

pub struct ClientFactory {
    #[allow(dead_code)]
    config: Arc<crate::config::GatewayConfig>,
}

impl ClientFactory {
    pub fn new(config: Arc<crate::config::GatewayConfig>) -> Self {
        Self { config }
    }

    pub async fn create_client(&self, provider_config: &ProviderConfig) -> GatewayResult<Arc<dyn LlmClient>> {
        let client: Arc<dyn LlmClient> = match provider_config.provider_type {
            ProviderType::OpenRouter => Arc::new(OpenRouterClient::new(provider_config.clone())?),
            ProviderType::Ollama => Arc::new(OllamaClient::new(provider_config.clone())?),
            ProviderType::Mock => Arc::new(MockClient::new(provider_config.clone())),
            ProviderType::OpenAI => Arc::new(OpenRouterClient::new(provider_config.clone())?),
            ProviderType::Anthropic => Arc::new(OpenRouterClient::new(provider_config.clone())?),
            ProviderType::Custom => Arc::new(OpenRouterClient::new(provider_config.clone())?),
        };
        Ok(client)
    }
}