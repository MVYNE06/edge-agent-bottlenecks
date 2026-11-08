@echo off
title Vivian AI + Autonomous Orchestrator Launcher

:: Set your local orchestrator token (minimum 24 characters)
set "ORCHESTRATOR_TOKEN=your-random-secret-token-at-least-24-characters-long"

echo Starting CPU-optimized llama-server...
:: Hardware flags: -ngl 0 (pure CPU), -t 6 (6 Zen 3 cores), -c 4096 context, -b 512 batch, -ub 512 ubatch
start "llama-server (Qwen 3.5-2B CPU)" "llama-server.exe" -m "models/Qwen3.5-2B-UD-Q4_K_XL.gguf" -ngl 0 -t 6 -c 4096 -b 512 -ub 512 --cache-reuse 256 --port 8080 --jinja

echo Waiting 5 seconds for model engine to initialize...
timeout /t 5 /nobreak >nul

echo Starting Autonomous Orchestrator (with Web + Telegram Bridge)...
start "Vivian Autonomous Orchestrator" powershell -NoExit -Command "$env:ORCHESTRATOR_TOKEN='%ORCHESTRATOR_TOKEN%'; python orchestrator.py"

echo.
echo All engines launched! You can minimize these windows.
timeout /t 3 >nul
exit
