//! RPC proxy request handling

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::allowlist::{
    is_method_allowed, needs_param_validation, validate_params, ALLOWED_METHODS,
};
use crate::config::{Backend, Config};

/// Application state shared across handlers
pub struct AppState {
    pub config: Config,
    pub client: Client,
    /// Pre-computed auth header for default backend
    pub default_auth_header: String,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        // Pre-compute the default authorization header
        let credentials = format!(
            "{}:{}",
            config.default_backend.user, config.default_backend.password
        );
        let default_auth_header = format!("Basic {}", BASE64.encode(credentials.as_bytes()));

        Ok(Self {
            config,
            client,
            default_auth_header,
        })
    }

    /// Make auth header for a specific backend
    fn make_auth_header(backend: &Backend) -> String {
        let credentials = format!("{}:{}", backend.user, backend.password);
        format!("Basic {}", BASE64.encode(credentials.as_bytes()))
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
    #[allow(dead_code)]
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

    #[error("Authentication failed")]
    AuthFailed,

    #[error("IP not allowed for authenticated access: {0}")]
    IpNotAllowed(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, message) = match &self {
            ProxyError::MethodNotAllowed(m) => {
                (StatusCode::OK, -32601, format!("Method not allowed: {}", m))
            }
            ProxyError::InvalidParams(m) => (StatusCode::OK, -32602, m.clone()),
            ProxyError::BackendError(m) => {
                (StatusCode::OK, -32603, format!("Internal error: {}", m))
            }
            ProxyError::AuthFailed => (
                StatusCode::UNAUTHORIZED,
                -32001,
                "Invalid credentials".to_string(),
            ),
            ProxyError::IpNotAllowed(ip) => (
                StatusCode::FORBIDDEN,
                -32002,
                format!("IP {} not allowed for authenticated access", ip),
            ),
        };

        let response = RpcResponse {
            result: Value::Null,
            error: Some(RpcError { code, message }),
            id: Value::Null,
        };

        (status, Json(response)).into_response()
    }
}

/// Extract real client IP from X-Forwarded-For header or connection address
/// X-Forwarded-For format: "client, proxy1, proxy2, ..."
/// We take the first (leftmost) IP as the original client
fn get_real_client_ip(headers: &HeaderMap, conn_addr: IpAddr) -> IpAddr {
    // Try X-Forwarded-For header first
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP in the chain (original client)
            if let Some(first_ip) = xff_str.split(',').next() {
                let trimmed = first_ip.trim();
                if let Ok(ip) = IpAddr::from_str(trimmed) {
                    debug!(
                        "Using X-Forwarded-For IP: {} (full header: {})",
                        ip, xff_str
                    );
                    return ip;
                }
            }
        }
    }

    // Fall back to connection address
    debug!("Using connection IP: {}", conn_addr);
    conn_addr
}

/// Parse Basic auth header and extract credentials
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;

    if !auth_header.starts_with("Basic ") {
        return None;
    }

    let encoded = &auth_header[6..];
    let decoded = BASE64.decode(encoded).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;

    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

/// Handle incoming RPC requests
pub async fn handle_rpc(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<RpcRequest>,
) -> Result<impl IntoResponse, ProxyError> {
    let method = request.method.as_str();
    // Get real client IP (respects X-Forwarded-For from reverse proxy)
    let client_ip = get_real_client_ip(&headers, addr.ip());

    debug!("RPC request from {}: method={}", client_ip, method);

    // Check if client provided authentication
    if let Some((user, password)) = parse_basic_auth(&headers) {
        // Authenticated request - check IP whitelist first
        if !state.config.is_ip_allowed_for_auth(&client_ip) {
            warn!(
                "Authenticated request from non-whitelisted IP: {} (user: {})",
                client_ip, user
            );
            return Err(ProxyError::IpNotAllowed(client_ip.to_string()));
        }

        // Look up backend for these credentials
        if let Some(backend) = state.config.get_backend_for_credentials(&user, &password) {
            info!(
                "Authenticated request from {} (user: {}) -> {} method: {}",
                client_ip, user, backend.url, method
            );

            // Forward to specific backend with FULL access (no method filtering)
            let backend_request = json!({
                "method": request.method,
                "params": request.params,
                "id": request.id,
            });

            let auth_header = AppState::make_auth_header(backend);

            let response = state
                .client
                .post(&backend.url)
                .header("Content-Type", "application/json")
                .header("Authorization", auth_header)
                .json(&backend_request)
                .send()
                .await
                .map_err(|e| ProxyError::BackendError(e.to_string()))?;

            let body: Value = response
                .json()
                .await
                .map_err(|e| ProxyError::BackendError(e.to_string()))?;

            return Ok(Json(body));
        } else {
            warn!("Invalid credentials from {}: user={}", client_ip, user);
            return Err(ProxyError::AuthFailed);
        }
    }

    // Unauthenticated request - apply method filtering
    debug!("Public request from {}: method={}", client_ip, method);

    // Check if method is in allowlist
    if !is_method_allowed(method) {
        warn!("Blocked method from {}: {}", client_ip, method);
        return Err(ProxyError::MethodNotAllowed(method.to_string()));
    }

    // Check parameter restrictions for special methods
    if needs_param_validation(method) {
        if let Err(reason) = validate_params(method, &request.params) {
            warn!(
                "Blocked params for {} from {}: {}",
                method, client_ip, reason
            );
            return Err(ProxyError::InvalidParams(reason.to_string()));
        }
    }

    // Forward to default backend
    let backend_request = json!({
        "method": request.method,
        "params": request.params,
        "id": request.id,
    });

    let response = state
        .client
        .post(&state.config.default_backend.url)
        .header("Content-Type", "application/json")
        .header("Authorization", &state.default_auth_header)
        .json(&backend_request)
        .send()
        .await
        .map_err(|e| ProxyError::BackendError(e.to_string()))?;

    let body: Value = response
        .json()
        .await
        .map_err(|e| ProxyError::BackendError(e.to_string()))?;

    debug!("Backend response received for {}", method);

    Ok(Json(body))
}

/// Handle GET requests - show proxy info
pub async fn handle_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut methods: Vec<&str> = ALLOWED_METHODS.iter().copied().collect();
    methods.sort();

    Json(json!({
        "name": "DIVI RPC Proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "network": state.config.default_backend.network,
        "description": "Filtering proxy that allows only safe read-only RPC methods for public access",
        "public_methods": methods,
        "authenticated_access": {
            "description": "Provide Basic auth credentials matching a registered backend for full RPC access",
            "ip_restricted": true,
            "allowed_ips": state.config.auth_ip_whitelist
        },
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
        .post(&state.config.default_backend.url)
        .header("Content-Type", "application/json")
        .header("Authorization", &state.default_auth_header)
        .json(&request)
        .send()
        .await;

    match result {
        Ok(response) if response.status().is_success() => (
            StatusCode::OK,
            Json(json!({
                "status": "healthy",
                "network": state.config.default_backend.network,
                "backend": "connected"
            })),
        ),
        Ok(response) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unhealthy",
                "network": state.config.default_backend.network,
                "backend": "error",
                "details": format!("Backend returned status {}", response.status())
            })),
        ),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unhealthy",
                "network": state.config.default_backend.network,
                "backend": "disconnected",
                "details": e.to_string()
            })),
        ),
    }
}
