@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign-pbfilter.ps1" %*
set ERR=%ERRORLEVEL%
if not "%ERR%"=="0" (
    echo sign-pbfilter.ps1 failed with %ERR%
    pause
    exit /b %ERR%
)
pause
exit /b 0
