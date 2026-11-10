@echo off
echo ========================================================
echo Running BotShield Pytest Test Suite
echo ========================================================
cd /d %~dp0\..\backend
python -m pytest tests -v
echo.
echo ========================================================
echo Verifying Frontend TypeScript & Build
echo ========================================================
cd /d %~dp0\..\frontend
npm.cmd run build
pause
