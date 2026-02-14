#!/bin/bash
#
# DIVI RPC Proxy Installation Script
# Installs the filtering proxy between HAProxy and DIVI RPC nodes
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    log_error "Do not run this script as root. It will use sudo when needed."
    exit 1
fi

# Ensure Rust is installed
if ! command -v cargo &> /dev/null; then
    log_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Build the binary
log_info "Building divi-rpc-proxy..."
cd "$PROJECT_DIR"
cargo build --release

# Install binary
log_info "Installing binary to /usr/local/bin..."
sudo cp target/release/divi-rpc-proxy /usr/local/bin/
sudo chmod +x /usr/local/bin/divi-rpc-proxy

# Create config directory
log_info "Creating configuration directory..."
sudo mkdir -p /etc/divi-rpc-proxy
sudo chown ubuntu:ubuntu /etc/divi-rpc-proxy
sudo chmod 700 /etc/divi-rpc-proxy

# Prompt for credentials if env files don't exist
if [[ ! -f /etc/divi-rpc-proxy/testnet.env ]]; then
    log_info "Setting up testnet credentials..."
    read -sp "Enter testnet RPC password: " TESTNET_PASS
    echo
    echo "RPC_PASSWORD_TESTNET=$TESTNET_PASS" | sudo tee /etc/divi-rpc-proxy/testnet.env > /dev/null
    sudo chmod 600 /etc/divi-rpc-proxy/testnet.env
fi

if [[ ! -f /etc/divi-rpc-proxy/mainnet.env ]]; then
    log_info "Setting up mainnet credentials..."
    read -sp "Enter mainnet RPC password: " MAINNET_PASS
    echo
    echo "RPC_PASSWORD_MAINNET=$MAINNET_PASS" | sudo tee /etc/divi-rpc-proxy/mainnet.env > /dev/null
    sudo chmod 600 /etc/divi-rpc-proxy/mainnet.env
fi

# Install systemd services
log_info "Installing systemd services..."
sudo cp "$SCRIPT_DIR/divi-rpc-proxy-testnet.service" /etc/systemd/system/
sudo cp "$SCRIPT_DIR/divi-rpc-proxy-mainnet.service" /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start services
log_info "Enabling and starting services..."
sudo systemctl enable divi-rpc-proxy-testnet
sudo systemctl enable divi-rpc-proxy-mainnet
sudo systemctl start divi-rpc-proxy-testnet
sudo systemctl start divi-rpc-proxy-mainnet

# Check status
sleep 2
log_info "Checking service status..."
if systemctl is-active --quiet divi-rpc-proxy-testnet; then
    log_info "Testnet proxy: running on port 17081"
else
    log_error "Testnet proxy failed to start"
    sudo journalctl -u divi-rpc-proxy-testnet -n 20 --no-pager
fi

if systemctl is-active --quiet divi-rpc-proxy-mainnet; then
    log_info "Mainnet proxy: running on port 18081"
else
    log_error "Mainnet proxy failed to start"
    sudo journalctl -u divi-rpc-proxy-mainnet -n 20 --no-pager
fi

log_info ""
log_info "Installation complete!"
log_info ""
log_info "Next steps:"
log_info "1. Update HAProxy to point to the proxy ports (17081/18081)"
log_info "2. Run: sudo cp $SCRIPT_DIR/haproxy-update.cfg.snippet /tmp/"
log_info "3. Review and apply the HAProxy changes"
log_info "4. sudo systemctl reload haproxy"
log_info ""
log_info "Test with:"
log_info "  curl -X POST http://localhost:17081 -H 'Content-Type: application/json' -d '{\"method\":\"getblockcount\",\"params\":[],\"id\":1}'"
