# DIVI RPC Proxy

A security filtering proxy for DIVI cryptocurrency nodes. Sits between public clients and DIVI RPC endpoints, allowing only safe read-only methods for unauthenticated access.

## Features

- **Public Access (Unauthenticated)**: Only whitelisted read-only RPC methods allowed
- **Authenticated Access**: Full RPC access for whitelisted IPs with valid credentials
- **IP Whitelist**: Authenticated access restricted to specific IPs (default: 127.0.0.1 only)
- **Multi-Backend Routing**: Route authenticated requests to different backends based on credentials
- **Parameter Validation**: Special methods like `mnsync` have parameter restrictions
- **Health Endpoint**: `/health` for load balancer integration
- **Info Endpoint**: `GET /` shows available methods and configuration
- **Cross-Platform**: Builds for Linux, macOS, Windows, and Raspberry Pi

## Security Model

### Public Access (No Authentication)
- Only ~45 safe read-only methods allowed
- No credentials required
- Available from any IP

### Authenticated Access
- Full RPC access (all methods)
- Requires valid Basic auth credentials matching a configured backend
- **IP restricted** - only allowed from whitelisted IPs (default: `127.0.0.1`)
- Useful for local services like faucets, explorers, admin tools

### Blocked Methods (Public)
- `stop` - would shut down the node
- `dumpprivkey`, `dumpwallet`, `dumphdinfo` - expose private keys
- `sendtoaddress`, `sendfrom`, `sendmany` - send funds
- `importprivkey` - modify wallet
- `encryptwallet`, `walletpassphrase` - wallet security
- All other wallet modification methods

See `src/allowlist.rs` for the complete list of allowed public methods.

## Installation

### From Release Binaries

Download the appropriate binary for your platform from the [Releases](https://github.com/DiviDomains/divi-rpc-proxy/releases) page.

### From Source

```bash
# Clone the repository
git clone https://github.com/DiviDomains/divi-rpc-proxy.git
cd divi-rpc-proxy

# Build release binary
cargo build --release

# Binary will be at target/release/divi-rpc-proxy
```

## Usage

### Basic (Public Access Only)

```bash
divi-rpc-proxy \
    --listen-addr 127.0.0.1 \
    --listen-port 17081 \
    --backend-url http://127.0.0.1:52591 \
    --rpc-user privatedivi \
    --rpc-password "your-rpc-password" \
    --network testnet
```

### With Multiple Backends for Authenticated Routing

```bash
divi-rpc-proxy \
    --listen-addr 127.0.0.1 \
    --listen-port 17081 \
    --backend-url http://127.0.0.1:52591 \
    --rpc-user privatedivi \
    --rpc-password "default-password" \
    --network testnet \
    --auth-backend "admin:adminpass@http://127.0.0.1:52591" \
    --auth-backend "faucet:faucetpass@http://127.0.0.1:52592" \
    --auth-ip-whitelist 127.0.0.1,10.0.0.5,192.168.1.100
```

### Environment Variables

All options can also be set via environment variables:

| Option | Environment Variable | Default |
|--------|---------------------|---------|
| `--listen-addr` | `LISTEN_ADDR` | `127.0.0.1` |
| `--listen-port` | `LISTEN_PORT` | `17081` |
| `--backend-url` | `BACKEND_URL` | `http://127.0.0.1:52591` |
| `--rpc-user` | `RPC_USER` | `privatedivi` |
| `--rpc-password` | `RPC_PASSWORD` | (required) |
| `--network` | `NETWORK` | `testnet` |
| `--auth-backend` | `AUTH_BACKENDS` | (none) |
| `--auth-ip-whitelist` | `AUTH_IP_WHITELIST` | `127.0.0.1` |

### Systemd Service

See `deploy/` directory for systemd service files.

## API

### POST / - RPC Endpoint

**Public (unauthenticated) - filtered methods only:**
```bash
curl -X POST http://localhost:17081 \
    -H 'Content-Type: application/json' \
    -d '{"method":"getblockcount","params":[],"id":1}'
```

**Authenticated - full access (from whitelisted IP):**
```bash
curl -X POST http://localhost:17081 \
    -u "privatedivi:your-password" \
    -H 'Content-Type: application/json' \
    -d '{"method":"sendtoaddress","params":["addr",1],"id":1}'
```

### GET / - Info

Returns proxy info, allowed public methods, and configuration.

### GET /health - Health Check

Returns health status for load balancer integration.

## Architecture

```
                                    ┌─────────────────────────────────┐
                                    │         DIVI RPC Proxy          │
                                    │                                 │
[Public Client] ──────────────────▶ │  No Auth: Filter methods       │
        (no auth)                   │  ────────────────────────────▶ │ ──▶ [Default Backend]
                                    │                                 │
                                    │                                 │
[Local Service] ──────────────────▶ │  With Auth + Whitelisted IP:  │
  (with Basic Auth)                 │  Full access, route by creds  │ ──▶ [Matched Backend]
  (e.g., faucet, explorer)          │                                 │
                                    └─────────────────────────────────┘
```

## License

MIT License

## Contributing

Pull requests welcome. Please ensure all tests pass:

```bash
cargo test
```
