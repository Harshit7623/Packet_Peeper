#!/bin/bash
echo "========================================"
echo "  Packet Peeper - Starting Frontend"
echo "========================================"
echo

cd "$(dirname "$0")/frontend"

echo "Installing dependencies..."
npm install

echo
echo "Starting frontend development server..."
echo "Frontend will be available at: http://localhost:5173"
echo
npm run dev
