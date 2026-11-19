@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-RansomGuard.ps1"
exit /b %errorlevel%
