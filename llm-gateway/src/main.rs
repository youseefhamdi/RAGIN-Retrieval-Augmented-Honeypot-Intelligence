use std::sync::Arc;
use tokio::signal;
use tracing::{info, error};
use axum::{Router, routing::{post, get}, Json, extract::{State, Path}, http::StatusCode};
use llm_gateway::{GatewayBuilder, GatewayConfig, ChatRequest, ChatResponse, CostEstimate, ModelCatalog, ModelConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting RAGIN LLM Gateway");

    // Load configuration
    let config = GatewayConfig::load()?;
    config.validate()?;
    info!("Configuration loaded and validated");

    // Build gateway
    let gateway = GatewayBuilder::new(config).build().await?;
    let gateway = Arc::new(gateway);
    info!("Gateway built successfully");

    // Start metrics server if enabled
    if gateway.config().metrics.enabled {
        let metrics_port = gateway.config().metrics.prometheus_port;
        let gateway_clone = gateway.clone();
        tokio::spawn(async move {
            if let Err(e) = start_metrics_server(metrics_port, gateway_clone).await {
                error!("Metrics server error: {}", e);
            }
        });
        info!("Metrics server started on port {}", metrics_port);
    }

    // Start HTTP server
    let server_addr = format!("{}:{}", gateway.config().server.host, gateway.config().server.port);
    let listener = tokio::net::TcpListener::bind(&server_addr).await?;
    info!("HTTP server listening on {}", server_addr);

    // Graceful shutdown
    let shutdown_signal = async {
        signal::ctrl_c().await.expect("Failed to listen for shutdown signal");
        info!("Shutdown signal received");
    };

    tokio::select! {
        _ = run_server(listener, gateway) => {},
        _ = shutdown_signal => {},
    }

    info!("Gateway shutdown complete");
    Ok(())
}

async fn run_server(listener: tokio::net::TcpListener, gateway: Arc<llm_gateway::Gateway>) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/models", get(list_models))
        .route("/v1/models/:model", get(get_model))
        .route("/v1/cost/estimate", post(estimate_cost))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics))
        .with_state(gateway);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn chat_completions(
    State(gateway): State<Arc<llm_gateway::Gateway>>,
    Json(request): Json<ChatRequest>,
) -> Result<Json<ChatResponse>, (StatusCode, String)> {
    let model = request.model.clone();
    let start = std::time::Instant::now();
    info!(request_id = %uuid::Uuid::new_v4(), model = %model, "POST /v1/chat/completions");
    let res = gateway.generate(request).await;
    info!(elapsed_ms = start.elapsed().as_millis(), model = %model, success = res.is_ok(), "POST /v1/chat/completions done");
    res
        .map(Json)
        .map_err(|e| (e.status_code(), e.to_string()))
}

async fn list_models(
    State(gateway): State<Arc<llm_gateway::Gateway>>,
) -> Result<Json<ModelCatalog>, (StatusCode, String)> {
    gateway.get_models().await
        .map(Json)
        .map_err(|e| (e.status_code(), e.to_string()))
}

async fn get_model(
    State(gateway): State<Arc<llm_gateway::Gateway>>,
    Path(model): Path<String>,
) -> Result<Json<ModelConfig>, (StatusCode, String)> {
    gateway.config().models.get(&model)
        .cloned()
        .map(Json)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Model not found: {}", model)))
}

async fn estimate_cost(
    State(gateway): State<Arc<llm_gateway::Gateway>>,
    Json(request): Json<ChatRequest>,
) -> Result<Json<CostEstimate>, (StatusCode, String)> {
    gateway.estimate_cost(&request).await
        .map(Json)
        .map_err(|e| (e.status_code(), e.to_string()))
}

async fn health_check(
    State(gateway): State<Arc<llm_gateway::Gateway>>,
) -> Json<serde_json::Value> {
    let health = gateway.health_check().await;
    Json(serde_json::json!({
        "status": "healthy",
        "providers": health,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn metrics(
    State(gateway): State<Arc<llm_gateway::Gateway>>,
) -> String {
    gateway.metrics().export_prometheus()
}

async fn start_metrics_server(port: u16, gateway: Arc<llm_gateway::Gateway>) -> Result<(), Box<dyn std::error::Error>> {
    use axum::routing::get;
    let app = Router::new().route("/metrics", get(move || {
        let gw = gateway.clone();
        async move { gw.metrics().export_prometheus() }
    }));
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}