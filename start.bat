@echo off
echo Starting ML Service...
start cmd /k "cd ml_service && python app.py"

echo Starting Backend...
start cmd /k "cd backend && npm run dev"

echo Starting Frontend...
start cmd /k "cd frontend && npm run dev"

echo All services are starting in new windows!
