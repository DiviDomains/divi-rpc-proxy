//! DIVI RPC Filtering Proxy
//!
//! A security proxy that sits between public clients and DIVI RPC nodes.
//! Only allows whitelisted read-only methods, blocking dangerous operations
//! like dumpprivkey, sendtoaddress, stop, etc.

mod allowlist;
mod config;
mod proxy;

use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::config::Config;
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

    /// Backend RPC URL (the actual DIVI node)
    #[arg(long, env = "BACKEND_URL", default_value = "http://127.0.0.1:52591")]
    backend_url: String,

    /// Backend RPC username
    #[arg(long, env = "RPC_USER", default_value = "privatedivi")]
    rpc_user: String,

    /// Backend RPC password
    #[arg(long, env = "RPC_PASSWORD")]
    rpc_password: String,

    /// Network name for logging (testnet/mainnet)
    #[arg(long, env = "NETWORK", default_value = "testnet")]
    network: String,
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

    info!(
        "Starting DIVI RPC Proxy for {} network",
        args.network
    );
    info!("Backend: {}", args.backend_url);
    info!(
        "Allowed methods: {} read-only methods",
        allowlist::ALLOWED_METHODS.len()
    );

    let config = Config {
        backend_url: args.backend_url,
        rpc_user: args.rpc_user,
        rpc_password: args.rpc_password,
        network: args.network,
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

    axum::serve(listener, app).await?;

    Ok(())
}
