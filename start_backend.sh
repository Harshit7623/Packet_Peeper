#!/bin/bash
# Quick Start Script for Packet Peeper Backend
# Run this script to set up and start the backend

set -e  # Exit on error

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
echo -e "${BLUE}[1/5]${NC} Checking Python version..."
python_version=$(python --version 2>&1 | grep -oP '(?<=Python )\d+\.\d+')
echo -e "${GREEN}✓${NC} Python $python_version found"
echo ""

# Step 2: Create virtual environment (if needed)
if [ ! -d "venv" ]; then
    echo -e "${BLUE}[2/5]${NC} Creating virtual environment..."
    python -m venv venv
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo -e "${BLUE}[2/5]${NC} Virtual environment already exists"
    echo -e "${GREEN}✓${NC} Skipping creation"
fi
echo ""

# Step 3: Activate virtual environment and install dependencies
echo -e "${BLUE}[3/5]${NC} Installing dependencies..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # Windows
    source venv/Scripts/activate
else
    # Linux/macOS
    source venv/bin/activate
fi

pip install --upgrade pip -q
pip install -r backend/requirements.txt -q
echo -e "${GREEN}✓${NC} Dependencies installed"
echo ""

# Step 4: Run verification
echo -e "${BLUE}[4/5]${NC} Verifying installation..."
cd backend
python verify_backend.py
VERIFY_RESULT=$?
echo ""

if [ $VERIFY_RESULT -ne 0 ]; then
    echo -e "${RED}✗${NC} Verification failed!"
    echo "Please fix the issues above and try again."
    exit 1
fi

# Step 5: Get network interface
echo -e "${BLUE}[5/5]${NC} Detecting network interface..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    echo "Available interfaces:"
    python -c "from scapy.all import conf; [print(f'  - {iface}') for iface in conf.ifaces]"
    echo ""
    read -p "Enter interface name (e.g., Wi-Fi): " INTERFACE
else
    echo "Available interfaces:"
    ip link show | grep "^[0-9]" | awk '{print "  - " $2}' | sed 's/:$//'
    echo ""
    read -p "Enter interface name (e.g., eth0): " INTERFACE
fi

if [ -z "$INTERFACE" ]; then
    INTERFACE="Wi-Fi"
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
echo -e "${YELLOW}→${NC} Logs: logs/packet_peeper.log"
echo ""
echo "To stop the server, press Ctrl+C"
echo ""

# Start the backend
python app.py "$INTERFACE"
