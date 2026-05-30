@echo off
setlocal

set SCRIPT_DIR=%~dp0
pushd %SCRIPT_DIR%\..

pyinstaller --clean --noconfirm "%SCRIPT_DIR%packet_peeper_backend.spec"

echo Backend binary built at: %CD%\dist\packet_peeper_backend.exe
popd

endlocal
