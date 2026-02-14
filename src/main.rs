//! DIVI RPC Filtering Proxy
//!
//! A security proxy that sits between public clients and DIVI RPC nodes.
//!
//! Two modes of operation:
//! 1. Public (unauthenticated): Only whitelisted read-only methods allowed
//! 2. Authenticated: Full RPC access for whitelisted IPs with valid credentials

mod allowlist;
mod config;
mod proxy;

use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::config::{Backend, Config};
use crate::proxy::AppState;

#[derive(Parser, Debug)]
#[command(name = "divi-rpc-proxy")]
#[command(about = "Filtering RPC proxy for DIVI nodes")]
struct Args {
    /// Listen address
    #[arg(long, env = "LISTEN_ADDR", default_value = "127.0.0.1")]
    listen_addr: String,

    /// Listen port
    #[arg(long, env = "LISTEN_PORT", default_value = "17081")]
    listen_port: u16,

    /// Default backend RPC URL (for public/unauthenticated requests)
    #[arg(long, env = "BACKEND_URL", default_value = "http://127.0.0.1:52591")]
    backend_url: String,

    /// Default backend RPC username
    #[arg(long, env = "RPC_USER", default_value = "privatedivi")]
    rpc_user: String,

    /// Default backend RPC password
    #[arg(long, env = "RPC_PASSWORD")]
    rpc_password: String,

    /// Network name for logging (testnet/mainnet)
    #[arg(long, env = "NETWORK", default_value = "testnet")]
    network: String,

    /// Additional backends for authenticated routing (format: user:pass@url)
    /// Can be specified multiple times
    #[arg(long = "auth-backend", env = "AUTH_BACKENDS", value_delimiter = ',')]
    auth_backends: Vec<String>,

    /// IP addresses allowed for authenticated access (comma-separated)
    /// Default: 127.0.0.1
    #[arg(
        long,
        env = "AUTH_IP_WHITELIST",
        value_delimiter = ',',
        default_value = "127.0.0.1"
    )]
    auth_ip_whitelist: Vec<IpAddr>,
}

fn parse_auth_backend(spec: &str, network: &str) -> Option<(String, Backend)> {
    // Format: user:password@url
    let parts: Vec<&str> = spec.splitn(2, '@').collect();
    if parts.len() != 2 {
        tracing::warn!("Invalid auth-backend format: {}", spec);
        return None;
    }

    let creds: Vec<&str> = parts[0].splitn(2, ':').collect();
    if creds.len() != 2 {
        tracing::warn!("Invalid credentials in auth-backend: {}", spec);
        return None;
    }

    let user = creds[0].to_string();
    let password = creds[1].to_string();
    let url = parts[1].to_string();
    let key = Config::make_credentials_key(&user, &password);

    Some((
        key,
        Backend {
            url,
            user,
            password,
            network: network.to_string(),
        },
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tower_http=debug")),
        )
        .init();

    let args = Args::parse();

    info!("Starting DIVI RPC Proxy for {} network", args.network);
    info!("Default backend: {}", args.backend_url);
    info!(
        "Allowed public methods: {} read-only methods",
        allowlist::ALLOWED_METHODS.len()
    );
    info!("Auth IP whitelist: {:?}", args.auth_ip_whitelist);

    // Build default backend
    let default_backend = Backend {
        url: args.backend_url,
        user: args.rpc_user,
        password: args.rpc_password,
        network: args.network.clone(),
    };

    // Parse authenticated backends
    let mut authenticated_backends = HashMap::new();

    // Add default backend credentials as an authenticated backend too
    // This allows local services to use the same credentials for full access
    let default_key =
        Config::make_credentials_key(&default_backend.user, &default_backend.password);
    authenticated_backends.insert(default_key.clone(), default_backend.clone());

    for spec in &args.auth_backends {
        if let Some((key, backend)) = parse_auth_backend(spec, &args.network) {
            info!(
                "Registered auth backend: {} -> {}",
                backend.user, backend.url
            );
            authenticated_backends.insert(key, backend);
        }
    }

    info!(
        "Authenticated backends registered: {}",
        authenticated_backends.len()
    );

    let config = Config {
        default_backend,
        authenticated_backends,
        auth_ip_whitelist: args.auth_ip_whitelist,
    };

    let state = Arc::new(AppState::new(config)?);

    // CORS layer - allow any origin for public API
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", post(proxy::handle_rpc))
        .route("/", get(proxy::handle_info))
        .route("/health", get(proxy::handle_health))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("{}:{}", args.listen_addr, args.listen_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("Listening on {}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
