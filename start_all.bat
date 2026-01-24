@echo off
echo ========================================
echo   Packet Peeper - Full Stack Startup
echo ========================================
echo.
echo This script will start both the backend and frontend.
echo.
echo [1/2] Starting Flask Backend (Port 5000)...
start "Packet Peeper Backend" cmd /c "cd /d %~dp0backend && python app.py"

echo.
echo Waiting for backend to initialize...
timeout /t 3 /nobreak > nul

echo.
echo [2/2] Starting React Frontend (Port 5173)...
start "Packet Peeper Frontend" cmd /c "cd /d %~dp0frontend && npm install && npm run dev"

echo.
echo ========================================
echo   Both services are starting...
echo ========================================
echo.
echo   Backend:  http://localhost:5000
echo   Frontend: http://localhost:5173
echo.
echo   Press any key to open the frontend in your browser...
pause > nul

start http://localhost:5173
