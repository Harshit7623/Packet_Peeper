@echo off
echo ========================================
echo   Packet Peeper - Starting Frontend
echo ========================================
echo.

cd /d "%~dp0frontend"

echo Installing dependencies...
call npm install

echo.
echo Starting frontend development server...
echo Frontend will be available at: http://localhost:5173
echo.
call npm run dev
