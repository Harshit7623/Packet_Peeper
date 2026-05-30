#!/bin/bash
# Quick Start Script for Packet Peeper Backend
# Run this script to set up and start the backend

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
VENV_DIR="$SCRIPT_DIR/.venv"

cd "$SCRIPT_DIR"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     🔒 PACKET PEEPER - BACKEND QUICK START SETUP          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Step 1: Check Python version
echo -e "${BLUE}[1/6]${NC} Checking Python version..."
PYTHON_BIN="python3"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

python_version=$($PYTHON_BIN --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python $python_version found"
echo ""

# Step 2: Create virtual environment (if needed)
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${BLUE}[2/6]${NC} Creating virtual environment..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo -e "${BLUE}[2/6]${NC} Virtual environment already exists"
    echo -e "${GREEN}✓${NC} Skipping creation"
fi
echo ""

# Step 3: Activate virtual environment and install dependencies
echo -e "${BLUE}[3/6]${NC} Installing dependencies..."
source "$VENV_DIR/bin/activate"

pip install --upgrade pip -q
pip install -r "$BACKEND_DIR/requirements.txt" -q
echo -e "${GREEN}✓${NC} Dependencies installed"
echo ""

# Step 4: Run verification
echo -e "${BLUE}[4/6]${NC} Verifying installation..."
cd "$BACKEND_DIR"
python verify_backend.py
VERIFY_RESULT=$?
echo ""

if [ $VERIFY_RESULT -ne 0 ]; then
    echo -e "${RED}✗${NC} Verification failed!"
    echo "Please fix the issues above and try again."
    exit 1
fi

# Step 5: Configure packet capture permissions (Linux)
echo -e "${BLUE}[5/6]${NC} Configuring packet capture permissions..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PYTHON_CAP_TARGET="$VENV_DIR/bin/python"
    if command -v getcap >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
        cap_status=$(getcap "$PYTHON_CAP_TARGET" 2>/dev/null || true)
        if [[ "$cap_status" != *"cap_net_raw"* ]]; then
            echo -e "${YELLOW}⚠${NC} Packet capture requires CAP_NET_RAW/CAP_NET_ADMIN."
            read -p "Grant capabilities to $PYTHON_CAP_TARGET using sudo? [y/N]: " GRANT_CAPS
            if [[ "$GRANT_CAPS" =~ ^[Yy]$ ]]; then
                sudo setcap cap_net_raw,cap_net_admin=eip "$PYTHON_CAP_TARGET" || true
                cap_status=$(getcap "$PYTHON_CAP_TARGET" 2>/dev/null || true)
            fi
        fi

        if [[ "$cap_status" == *"cap_net_raw"* ]]; then
            echo -e "${GREEN}✓${NC} Packet capture capabilities set"
        else
            echo -e "${YELLOW}⚠${NC} Capabilities not set. You may need to run with sudo."
        fi
    else
        echo -e "${YELLOW}⚠${NC} setcap/getcap not found. Install libcap and rerun, or use sudo."
    fi
else
    echo -e "${YELLOW}⚠${NC} Packet capture permissions are OS-specific. Skipping."
fi
echo ""

# Step 5: Get network interface
echo -e "${BLUE}[6/6]${NC} Detecting network interface..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    echo "Available interfaces:"
    python -c "from scapy.all import conf; [print(f'  - {iface}') for iface in conf.ifaces]"
    echo ""
    read -p "Enter interface name (e.g., Wi-Fi): " INTERFACE
else
    echo "Available interfaces:"
    ip link show | awk -F': ' '/^[0-9]+: /{print "  - " $2}'
    echo ""
    read -p "Enter interface name (press Enter for auto): " INTERFACE
fi

if [ -z "$INTERFACE" ]; then
    INTERFACE="auto"
    echo -e "${YELLOW}⚠${NC} No interface specified, using default: $INTERFACE"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo -e "${GREEN}✓ SETUP COMPLETE!${NC}"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Starting Packet Peeper backend..."
echo -e "${YELLOW}→${NC} Interface: $INTERFACE"
echo -e "${YELLOW}→${NC} Backend: http://localhost:5000"
echo -e "${YELLOW}→${NC} Logs: backend/logs/packet_peeper.log"
echo ""
echo "To stop the server, press Ctrl+C"
echo ""

# Start the backend
python app.py "$INTERFACE"
