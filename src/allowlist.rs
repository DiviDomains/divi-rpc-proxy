//! Allowlist of safe RPC methods
//!
//! Only methods in this list will be forwarded to the backend.
//! All other methods are blocked with a clear error message.
//!
//! Criteria for inclusion:
//! - Read-only operations only
//! - No private key exposure
//! - No wallet balance/transaction history exposure
//! - No fund movement capability
//! - No node control (stop, restart, etc.)

use std::collections::HashSet;
use std::sync::LazyLock;

/// Set of allowed RPC method names
pub static ALLOWED_METHODS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        // === Blockchain (read-only) ===
        "getbestblockhash",
        "getblock",
        "getblockchaininfo",
        "getblockcount",
        "getblockhash",
        "getblockheader",
        "getchaintips",
        "getdifficulty",
        "getmempoolinfo",
        "getrawmempool",
        "gettxout",
        "gettxoutsetinfo",
        "verifychain",
        "getlotteryblockwinners",
        "reverseblocktransactions",
        // === Network info (read-only) ===
        "getconnectioncount",
        "getnettotals",
        "getnetworkinfo",
        "getpeerinfo",
        "ping",
        // Note: getaddednodeinfo excluded - reveals node configuration

        // === General info ===
        "getinfo",
        "help",
        // Note: "stop" explicitly NOT included

        // === Mining info (read-only) ===
        "getmininginfo",
        // Note: generateblock, setgenerate excluded - can affect chain

        // === Raw transaction decoding (read-only) ===
        "decoderawtransaction",
        "decodescript",
        "getrawtransaction",
        // Note: sendrawtransaction excluded - can send funds
        // Note: signrawtransaction excluded - can sign transactions

        // === Address index queries (read-only, public chain data) ===
        "getaddressbalance",
        "getaddressdeltas",
        "getaddresstxids",
        "getaddressutxos",
        "getspentinfo",
        // === Utility (read-only) ===
        "validateaddress",
        "verifymessage",
        "createmultisig",
        // === Masternode info (read-only) ===
        "getmasternodecount",
        "getmasternodestatus",
        "getmasternodewinners",
        "listmasternodes",
        "listmnbroadcasts",
        // Note: startmasternode, setupmasternode, etc. excluded

        // === Sync status (read-only) ===
        // mnsync with "status" param only - handled specially in proxy

        // === Spork info (read-only) ===
        // spork without value param - handled specially in proxy
    ])
});

/// Methods that need special parameter validation
pub static PARAM_RESTRICTED_METHODS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "mnsync", // Only allow "status" parameter
        "spork",  // Only allow read (no value parameter)
    ])
});

/// Check if a method is allowed
pub fn is_method_allowed(method: &str) -> bool {
    ALLOWED_METHODS.contains(method)
}

/// Check if method needs parameter validation
pub fn needs_param_validation(method: &str) -> bool {
    PARAM_RESTRICTED_METHODS.contains(method)
}

/// Validate parameters for restricted methods
/// Returns Ok(()) if params are safe, Err(reason) if not
pub fn validate_params(method: &str, params: &serde_json::Value) -> Result<(), &'static str> {
    match method {
        "mnsync" => {
            // Only allow "status" parameter
            if let Some(arr) = params.as_array() {
                if arr.len() == 1 {
                    if let Some(s) = arr[0].as_str() {
                        if s == "status" {
                            return Ok(());
                        }
                    }
                }
            }
            Err("mnsync only allows 'status' parameter")
        }
        "spork" => {
            // Only allow read (single param or no params)
            // Block if there's a second param (which would set a value)
            if let Some(arr) = params.as_array() {
                if arr.len() <= 1 {
                    return Ok(());
                }
            }
            Err("spork write operations not allowed")
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_methods_allowed() {
        assert!(is_method_allowed("getblockcount"));
        assert!(is_method_allowed("getinfo"));
        assert!(is_method_allowed("getpeerinfo"));
    }

    #[test]
    fn test_dangerous_methods_blocked() {
        assert!(!is_method_allowed("stop"));
        assert!(!is_method_allowed("dumpprivkey"));
        assert!(!is_method_allowed("dumpwallet"));
        assert!(!is_method_allowed("dumphdinfo"));
        assert!(!is_method_allowed("sendtoaddress"));
        assert!(!is_method_allowed("sendrawtransaction"));
        assert!(!is_method_allowed("importprivkey"));
        assert!(!is_method_allowed("encryptwallet"));
        assert!(!is_method_allowed("walletpassphrase"));
        assert!(!is_method_allowed("backupwallet"));
    }

    #[test]
    fn test_mnsync_validation() {
        let status_params = serde_json::json!(["status"]);
        assert!(validate_params("mnsync", &status_params).is_ok());

        let reset_params = serde_json::json!(["reset"]);
        assert!(validate_params("mnsync", &reset_params).is_err());
    }

    #[test]
    fn test_spork_validation() {
        let read_params = serde_json::json!(["show"]);
        assert!(validate_params("spork", &read_params).is_ok());

        let write_params = serde_json::json!(["SPORK_NAME", 12345]);
        assert!(validate_params("spork", &write_params).is_err());
    }
}
