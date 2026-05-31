@echo off
:: Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /B
)

:: Ensure we are in the correct directory with the full path, not the short path
cd /d "%~dp0"
echo Starting ML Service...
start cmd /k "cd ml_service && python app.py"

echo Starting Backend...
start cmd /k "cd backend && npm run dev"

echo Starting Frontend...
start cmd /k "cd frontend && npm run dev"

echo Starting DNS Monitor...
start cmd /k "cd ml_service && python dns_monitor.py"

echo All services are starting in new windows!
