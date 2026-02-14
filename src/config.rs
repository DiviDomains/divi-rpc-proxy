//! Configuration for the RPC proxy

#[derive(Debug, Clone)]
pub struct Config {
    /// Backend RPC URL
    pub backend_url: String,
    /// RPC username for backend authentication
    pub rpc_user: String,
    /// RPC password for backend authentication
    pub rpc_password: String,
    /// Network name (testnet/mainnet) for logging
    pub network: String,
}
