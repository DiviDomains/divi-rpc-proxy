# DIVI RPC Proxy

A security filtering proxy for DIVI cryptocurrency nodes. Sits between public clients and DIVI RPC endpoints, allowing only safe read-only methods.

## Features

- **Method Allowlisting**: Only whitelisted RPC methods are forwarded
- **No Authentication Required**: Public clients don't need credentials
- **Backend Authentication**: Proxy handles RPC authentication internally
- **Parameter Validation**: Special methods like `mnsync` have parameter restrictions
- **Health Endpoint**: `/health` for load balancer integration
- **Info Endpoint**: `GET /` shows available methods
- **Cross-Platform**: Builds for Linux, macOS, Windows, and Raspberry Pi

## Security

The proxy blocks dangerous RPC methods including:
- `stop` - would shut down the node
- `dumpprivkey`, `dumpwallet`, `dumphdinfo` - expose private keys
- `sendtoaddress`, `sendfrom`, `sendmany` - send funds
- `importprivkey` - modify wallet
- `encryptwallet`, `walletpassphrase` - wallet security
- All other wallet modification methods

See `src/allowlist.rs` for the complete list of allowed methods.

## Installation

### From Release Binaries

Download the appropriate binary for your platform from the [Releases](https://github.com/AEZ-IO/divi-rpc-proxy/releases) page.

### From Source

```bash
# Clone the repository
git clone https://github.com/AEZ-IO/divi-rpc-proxy.git
cd divi-rpc-proxy

# Build release binary
cargo build --release

# Binary will be at target/release/divi-rpc-proxy
```

## Usage

```bash
divi-rpc-proxy \
    --listen-addr 127.0.0.1 \
    --listen-port 17081 \
    --backend-url http://127.0.0.1:52591 \
    --rpc-user privatedivi \
    --rpc-password "your-rpc-password" \
    --network testnet
```

### Environment Variables

All options can also be set via environment variables:
- `LISTEN_ADDR`
- `LISTEN_PORT`
- `BACKEND_URL`
- `RPC_USER`
- `RPC_PASSWORD`
- `NETWORK`

### Systemd Service

See `deploy/` directory for systemd service files.

## API

### POST / - RPC Endpoint

Send JSON-RPC requests:

```bash
curl -X POST http://localhost:17081 \
    -H 'Content-Type: application/json' \
    -d '{"method":"getblockcount","params":[],"id":1}'
```

### GET / - Info

Returns proxy info and list of allowed methods.

### GET /health - Health Check

Returns health status for load balancer integration.

## Architecture

```
[Public Client] --> [HAProxy:17080] --> [divi-rpc-proxy:17081] --> [DIVI Node:52591]
                         |                      |
                    No auth needed        Filters methods
                                          Adds authentication
```

## License

MIT License

## Contributing

Pull requests welcome. Please ensure all tests pass:

```bash
cargo test
```
