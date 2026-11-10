@echo off
echo ========================================================
echo Starting BotShield Frontend Dev Server (Vite / React)
echo ========================================================
cd /d %~dp0\..\frontend
npm.cmd run dev
pause
