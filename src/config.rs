//! Configuration for the RPC proxy

use std::collections::HashMap;
use std::net::IpAddr;

/// Backend RPC endpoint configuration
#[derive(Debug, Clone)]
pub struct Backend {
    /// Backend RPC URL
    pub url: String,
    /// RPC username for backend authentication
    pub user: String,
    /// RPC password for backend authentication
    pub password: String,
    /// Network name (testnet/mainnet) for logging
    pub network: String,
}

/// Main configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Default backend for unauthenticated (public) requests
    pub default_backend: Backend,

    /// Additional backends keyed by "user:password" for authenticated routing
    /// When a client provides credentials matching a key, requests are routed
    /// to that backend with full method access (no filtering)
    pub authenticated_backends: HashMap<String, Backend>,

    /// IP addresses allowed to make authenticated requests
    /// Defaults to only 127.0.0.1 if not specified
    pub auth_ip_whitelist: Vec<IpAddr>,
}

impl Config {
    /// Create credentials key for lookup
    pub fn make_credentials_key(user: &str, password: &str) -> String {
        format!("{}:{}", user, password)
    }

    /// Check if an IP is allowed for authenticated access
    pub fn is_ip_allowed_for_auth(&self, ip: &IpAddr) -> bool {
        self.auth_ip_whitelist.contains(ip)
    }

    /// Look up backend by credentials
    pub fn get_backend_for_credentials(&self, user: &str, password: &str) -> Option<&Backend> {
        let key = Self::make_credentials_key(user, password);
        self.authenticated_backends.get(&key)
    }
}
