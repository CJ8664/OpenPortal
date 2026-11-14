@echo off
title OpenPortal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0OpenPortal.ps1" %*
echo.
pause
