@echo off
REM BYOVD Setup for pbfilter.sys - Batch script version
REM Bypasses Driver Signature Enforcement using vulnerable signed drivers
REM Usage: runas administrator byovd.bat

echo ========================================
echo BYOVD Setup for pbfilter.sys
echo ========================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator!
    echo Open Command Prompt as Administrator and re-run.
    pause
    exit /b 1
)

echo [STEP] Checking for pbfilter.sys...
if not exist "pbfilter.sys" (
    echo [WARN] pbfilter.sys not found in current directory
    echo Please build pbfilter.sys first or run from PeerBlock directory
) else (
    echo [OK] pbfilter.sys found
)

echo.
echo [STEP] Checking for BYOVD driver (dxgkrnl.sys)...
if exist "C:\Windows\System32\drivers\dxgkrnl.sys" (
    echo [OK] BYOVD driver found at C:\Windows\System32\drivers\dxgkrnl.sys
) else (
    echo [WARN] BYOVD driver not found, will proceed anyway
)

echo.
echo [STEP] Enabling nointegritychecks...
bcdedit /set nointegritychecks on
if %errorLevel% equ 0 (
    echo [OK] nointegritychecks enabled
) else (
    echo [ERROR] Failed to enable nointegritychecks
    pause
    exit /b 1
)

echo.
echo [STEP] Creating BYOVD service...
sc create dxgkrnlSvc binPath= C:\Windows\System32\drivers\dxgkrnl.sys type= kernel
if %errorLevel% equ 0 (
    echo [OK] Service dxgkrnlSvc created
) else (
    echo [WARN] Service may already exist
)

echo.
echo [STEP] Starting BYOVD service...
sc start dxgkrnlSvc
if %errorLevel% equ 0 (
    echo [OK] Service started
) else (
    echo [WARN] Service may already be running
)

echo.
echo ========================================
echo BYOVD Setup Complete!
echo ========================================
echo.
echo Next steps:
echo   1. Reboot your computer
echo   2. Run peerblock.exe as Administrator
echo   3. pbfilter.sys will load with DSE bypassed
echo.
echo To undo:
echo   bcdedit /set nointegritychecks off
echo   sc delete dxgkrnlSvc
echo.
pause
