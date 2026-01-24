@echo off
REM Quick Start Script for Packet Peeper Backend (Windows)
REM Run this script to set up and start the backend

setlocal enabledelayedexpansion

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║     ^^ PACKET PEEPER - BACKEND QUICK START SETUP          ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

REM Step 1: Check Python version
echo [1/5] Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.8+
    pause
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo. [✓] Python %PYTHON_VERSION% found
echo.

REM Step 2: Create virtual environment (if needed)
if not exist "venv" (
    echo [2/5] Creating virtual environment...
    python -m venv venv
    echo. [✓] Virtual environment created
) else (
    echo [2/5] Virtual environment already exists
    echo. [✓] Skipping creation
)
echo.

REM Step 3: Activate virtual environment and install dependencies
echo [3/5] Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip -q >nul 2>&1
pip install -r backend\requirements.txt -q
echo. [✓] Dependencies installed
echo.

REM Step 4: Run verification
echo [4/5] Verifying installation...
cd backend
python verify_backend.py
if errorlevel 1 (
    echo. [×] Verification failed!
    echo Please fix the issues above and try again.
    pause
    exit /b 1
)
echo.

REM Step 5: Get network interface
echo [5/5] Detecting network interface...
echo Available interfaces:
python -c "from scapy.all import conf; [print(f'  - {iface}') for iface in conf.ifaces]"
echo.
set /p INTERFACE="Enter interface name (e.g., Wi-Fi): "

if "!INTERFACE!"=="" (
    set INTERFACE=Wi-Fi
    echo. [⚠] No interface specified, using default: !INTERFACE!
)

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo [✓] SETUP COMPLETE!
echo ╚════════════════════════════════════════════════════════════╝
echo.
echo Starting Packet Peeper backend...
echo. [→] Interface: !INTERFACE!
echo. [→] Backend: http://localhost:5000
echo. [→] Logs: logs\packet_peeper.log
echo.
echo To stop the server, press Ctrl+C
echo.

REM Start the backend
python app.py "!INTERFACE!"

cd ..
pause
