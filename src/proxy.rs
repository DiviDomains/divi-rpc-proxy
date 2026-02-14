//! RPC proxy request handling

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::allowlist::{is_method_allowed, needs_param_validation, validate_params, ALLOWED_METHODS};
use crate::config::Config;

/// Application state shared across handlers
pub struct AppState {
    pub config: Config,
    pub client: Client,
    pub auth_header: String,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        // Pre-compute the authorization header
        let credentials = format!("{}:{}", config.rpc_user, config.rpc_password);
        let auth_header = format!("Basic {}", BASE64.encode(credentials.as_bytes()));

        Ok(Self {
            config,
            client,
            auth_header,
        })
    }
}

/// JSON-RPC request structure
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub id: Value,
    #[serde(default)]
    pub jsonrpc: Option<String>,
}

/// JSON-RPC response structure
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub result: Value,
    pub error: Option<RpcError>,
    pub id: Value,
}

/// JSON-RPC error structure
#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

/// Proxy errors
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Method not allowed: {0}")]
    MethodNotAllowed(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Backend error: {0}")]
    BackendError(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> axum::response::Response {
        let (code, message) = match &self {
            ProxyError::MethodNotAllowed(m) => (-32601, format!("Method not allowed: {}", m)),
            ProxyError::InvalidParams(m) => (-32602, m.clone()),
            ProxyError::BackendError(m) => (-32603, format!("Internal error: {}", m)),
            ProxyError::InvalidRequest(m) => (-32600, m.clone()),
        };

        let response = RpcResponse {
            result: Value::Null,
            error: Some(RpcError { code, message }),
            id: Value::Null,
        };

        (StatusCode::OK, Json(response)).into_response()
    }
}

/// Handle incoming RPC requests
pub async fn handle_rpc(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RpcRequest>,
) -> Result<impl IntoResponse, ProxyError> {
    let method = request.method.as_str();

    debug!("RPC request: method={}", method);

    // Check if method is in allowlist
    if !is_method_allowed(method) {
        warn!("Blocked method: {}", method);
        return Err(ProxyError::MethodNotAllowed(method.to_string()));
    }

    // Check parameter restrictions for special methods
    if needs_param_validation(method) {
        if let Err(reason) = validate_params(method, &request.params) {
            warn!("Blocked params for {}: {}", method, reason);
            return Err(ProxyError::InvalidParams(reason.to_string()));
        }
    }

    // Forward to backend
    let backend_request = json!({
        "method": request.method,
        "params": request.params,
        "id": request.id,
    });

    let response = state
        .client
        .post(&state.config.backend_url)
        .header("Content-Type", "application/json")
        .header("Authorization", &state.auth_header)
        .json(&backend_request)
        .send()
        .await
        .map_err(|e| ProxyError::BackendError(e.to_string()))?;

    let body: Value = response
        .json()
        .await
        .map_err(|e| ProxyError::BackendError(e.to_string()))?;

    debug!("Backend response received");

    Ok(Json(body))
}

/// Handle GET requests - show proxy info
pub async fn handle_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut methods: Vec<&str> = ALLOWED_METHODS.iter().copied().collect();
    methods.sort();

    Json(json!({
        "name": "DIVI RPC Proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "network": state.config.network,
        "description": "Filtering proxy that allows only safe read-only RPC methods",
        "allowed_methods": methods,
        "usage": {
            "method": "POST",
            "content_type": "application/json",
            "body": {
                "method": "<method_name>",
                "params": ["<param1>", "<param2>"],
                "id": 1
            }
        }
    }))
}

/// Health check endpoint
pub async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Try to ping the backend
    let request = json!({
        "method": "getblockcount",
        "params": [],
        "id": "health",
    });

    let result = state
        .client
        .post(&state.config.backend_url)
        .header("Content-Type", "application/json")
        .header("Authorization", &state.auth_header)
        .json(&request)
        .send()
        .await;

    match result {
        Ok(response) if response.status().is_success() => {
            (StatusCode::OK, Json(json!({
                "status": "healthy",
                "network": state.config.network,
                "backend": "connected"
            })))
        }
        Ok(response) => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
                "status": "unhealthy",
                "network": state.config.network,
                "backend": "error",
                "details": format!("Backend returned status {}", response.status())
            })))
        }
        Err(e) => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
                "status": "unhealthy",
                "network": state.config.network,
                "backend": "disconnected",
                "details": e.to_string()
            })))
        }
    }
}
