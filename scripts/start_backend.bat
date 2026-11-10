@echo off
echo ========================================================
echo Starting BotShield Backend API Server (FastAPI / Uvicorn)
echo ========================================================
cd /d %~dp0\..\backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
pause
