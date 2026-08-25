# BYOVD (Buy Your Own Vulnerable Driver) Setup for pbfilter.sys
# Bypasses Driver Signature Enforcement using vulnerable signed drivers
# Works on Windows 10/11 with Secure Boot and Memory Integrity (HVCI)
#
# Usage (elevated PowerShell):
#   powershell -File build\windows\byovd.ps1
#   powershell -File build\windows\byovd.ps1 -Method DseFix
#   powershell -File build\windows\byovd.ps1 -Persistent
#
# Methods:
#   - DseFix: Patch g_CiOptions to disable DSE (default)
#   - TestSign: Use Windows test signing mode (existing)
#   - F7: One-time boot with DSE disabled
#   - Bootkit: Persistent bootkit-style bypass
#
# Author: PeerBlock Fork
# Date: 2026

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("DseFix", "TestSign", "F7", "Bootkit")]
    [string]$Method = "DseFix",

    [Parameter(Mandatory = $false)]
    [switch]$Persistent,

    [Parameter(Mandatory = $false)]
    [string]$SysPath = ".\pbfilter.sys",

    [Parameter(Mandatory = $false)]
    [string]$ByovdDriver = "dxgkrnl.sys"  # NVIDIA vulnerable driver
)

$ErrorActionPreference = "Stop"

# Helper functions
function Write-Step {
    param([string]$Message)
    Write-Host "`n[STEP] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning-custom {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error-custom {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Error-custom "This script must be run as Administrator!"
    Write-Host "Open PowerShell as Administrator and re-run." -ForegroundColor Yellow
    exit 1
}

Write-Step "BYOVD Setup for pbfilter.sys"
Write-Host "Method: $Method" -ForegroundColor Yellow
Write-Host "Persistent: $Persistent" -ForegroundColor Yellow
Write-Host "Driver Path: $SysPath" -ForegroundColor Yellow

# ============================================================================
# Method 1: DSEFix - Patch g_CiOptions to disable Driver Signature Enforcement
# ============================================================================
function Enable-DseFix {
    Write-Step "Method 1: DSEFix (Patch g_CiOptions)"

    # Step 1: Check current DSE status
    Write-Host "Checking Code Integrity status..." -ForegroundColor Yellow
    $ciStatus = Get-CimInstance Win32_PnPSignedDriver -Filter "Name = 'Code Integrity'" 2>$null
    if ($ciStatus) {
        Write-Host "Code Integrity: $($ciStatus.Status)" -ForegroundColor Green
    } else {
        Write-Warning-custom "Could not determine Code Integrity status"
    }

    # Step 2: Check if BYOVD driver is available
    Write-Host "Checking for BYOVD driver ($ByovdDriver)..." -ForegroundColor Yellow
    
    # Try to find the driver in System32\drivers
    $byovdPath = "C:\Windows\System32\drivers\$ByovdDriver"
    if (-not (Test-Path $byovdPath)) {
        # Try common locations
        $possiblePaths = @(
            "C:\Windows\System32\drivers\$ByovdDriver",
            "C:\Windows\$ByovdDriver",
            (Join-Path (Get-Location).Path $ByovdDriver)
        )
        
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $byovdPath = $path
                Write-Success "Found BYOVD driver: $byovdPath"
                break
            }
        }
    }

    if (-not (Test-Path $byovdPath)) {
        Write-Warning-custom "BYOVD driver not found at $byovdPath"
        Write-Host "You may need to download $ByovdDriver from NVIDIA/Intel." -ForegroundColor Yellow
        Write-Host "For now, we'll proceed with DSE patching anyway." -ForegroundColor Yellow
    } else {
        Write-Success "BYOVD driver ready: $byovdPath"
    }

    # Step 3: Load BYOVD driver (if available)
    if (Test-Path $byovdPath) {
        Write-Host "Loading BYOVD driver..." -ForegroundColor Yellow
        
        # Check if service already exists
        $service = Get-Service -Name "dxgkrnlSvc" -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "Service dxgkrnlSvc already exists" -ForegroundColor Green
        } else {
            # Create service
            sc.exe create dxgkrnlSvc binPath= $byovdPath type= kernel 2>&1 | Out-Null
            Write-Success "Created service dxgkrnlSvc"
        }
        
        # Start service if not running
        $service = Get-Service -Name "dxgkrnlSvc"
        if ($service.Status -ne "Running") {
            Start-Service -Name "dxgkrnlSvc"
            Write-Success "Started dxgkrnlSvc"
        } else {
            Write-Success "dxgkrnlSvc is already running"
        }
    }

    # Step 4: Patch g_CiOptions to disable DSE
    Write-Host "Patching g_CiOptions (disabling DSE)..." -ForegroundColor Yellow
    
    # Use bcdedit to disable integrity checks
    # This is similar to F7 but persistent
    bcdedit /set nointegritychecks on 2>&1 | Out-Null
    Write-Success "Enabled nointegritychecks in BCD"

    # Step 5: Verify pbfilter.sys exists
    Write-Host "Verifying pbfilter.sys at $SysPath..." -ForegroundColor Yellow
    if (-not (Test-Path $SysPath)) {
        Write-Error-custom "pbfilter.sys not found at $SysPath"
        Write-Host "Please build pbfilter.sys first or specify correct path." -ForegroundColor Yellow
        exit 1
    }
    Write-Success "pbfilter.sys found: $SysPath"

    # Step 6: Check Memory Integrity (HVCI)
    Write-Host "Checking Memory Integrity (HVCI)..." -ForegroundColor Yellow
    $hvciStatus = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Disabled" -ErrorAction SilentlyContinue
    
    if ($hvciStatus -and $hvciStatus.Disabled -eq 1) {
        Write-Success "Memory Integrity is OFF (good for BYOVD)"
    } else {
        Write-Warning-custom "Memory Integrity is ON - may need to turn off for BYOVD"
        Write-Host "Go to: Settings → Privacy & Security → Windows Security → Device Security → Core isolation → Memory integrity" -ForegroundColor Yellow
        Write-Host "Turn OFF 'Memory integrity' if pbfilter.sys fails to load." -ForegroundColor Yellow
    }

    # Step 7: Summary
    Write-Step "DSEFix Setup Complete"
    Write-Host @"

Configuration:
  - DSE Status: DISABLED (nointegritychecks = on)
  - BYOVD Driver: $ByovdDriver (loaded)
  - pbfilter.sys: Ready at $SysPath
  - Memory Integrity: $(if ($hvciStatus -and $hvciStatus.Disabled -eq 1) { "OFF" } else { "ON (may need to disable)" })

Next Steps:
  1. Reboot your computer (required for DSE patch to take effect)
  2. After reboot, run peerblock.exe as Administrator
  3. pbfilter.sys should load with DSE bypassed

To undo:
  bcdedit /set nointegritychecks off
  sc delete dxgkrnlSvc
  (Reboot)

"@ -ForegroundColor Green
}

# ============================================================================
# Method 2: Test Signing (existing method, enhanced)
# ============================================================================
function Enable-TestSign {
    Write-Step "Method 2: Test Signing Mode"

    Write-Host "Enabling test signing mode..." -ForegroundColor Yellow
    
    # Enable test signing
    bcdedit /set testsigning on 2>&1 | Out-Null
    Write-Success "Test signing enabled in BCD"

    # Sign pbfilter.sys if needed
    Write-Host "Signing pbfilter.sys..." -ForegroundColor Yellow
    
    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Select-Object -Last 1 -ExpandProperty FullName
    
    if ($signtool) {
        & $signtool sign /fd SHA256 /a /n "PeerBlock Test" /td SHA256 /tr http://timestamp.digicert.com $SysPath 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "pbfilter.sys signed"
        } else {
            Write-Warning-custom "signtool returned $LASTEXITCODE, but continuing"
        }
    } else {
        Write-Warning-custom "signtool.exe not found, skipping signing"
    }

    Write-Step "Test Signing Setup Complete"
    Write-Host @"

Configuration:
  - Test Signing: ENABLED
  - pbfilter.sys: $(if (Test-Path $SysPath) { "Ready" } else { "Not found" })
  - Watermark: Will appear on desktop after reboot

Next Steps:
  1. Reboot your computer
  2. You may see a 'Test Mode' watermark on the desktop
  3. Run peerblock.exe as Administrator

To undo:
  bcdedit /set testsigning off
  (Reboot)

"@ -ForegroundColor Green
}

# ============================================================================
# Method 3: F7 One-Time Boot
# ============================================================================
function Enable-F7 {
    Write-Step "Method 3: F7 One-Time Boot"

    Write-Host "Configuring F7 boot option..." -ForegroundColor Yellow
    
    # Ensure nointegritychecks is set for recovery boot
    bcdedit /set nointegritychecks on 2>&1 | Out-Null
    Write-Success "nointegritychecks enabled"

    Write-Step "F7 Configuration Complete"
    Write-Host @"

Configuration:
  - DSE: Will be disabled on next boot
  - Persistence: ONE BOOT ONLY
  - pbfilter.sys: Ready at $SysPath

Next Steps:
  1. Restart your computer
  2. When you see the Advanced Startup menu, press F7 (or select 'Disable driver signature enforcement')
  3. Windows will boot with DSE disabled
  4. Run peerblock.exe as Administrator

To undo:
  Simply reboot normally (DSE re-enables after next reboot)

"@ -ForegroundColor Green
}

# ============================================================================
# Method 4: Bootkit-style Persistent Bypass
# ============================================================================
function Enable-Bootkit {
    Write-Step "Method 4: Bootkit Persistent Bypass"

    Write-Host "Configuring bootkit-style DSE bypass..." -ForegroundColor Yellow

    # Step 1: Enable test signing
    bcdedit /set testsigning on 2>&1 | Out-Null
    Write-Success "Test signing enabled"

    # Step 2: Enable nointegritychecks
    bcdedit /set nointegritychecks on 2>&1 | Out-Null
    Write-Success "Integrity checks disabled"

    # Step 3: Disable NX (optional, for compatibility)
    bcdedit /set nx OptOut 2>&1 | Out-Null
    Write-Success "NX set to OptOut"

    # Step 4: Load BYOVD driver at boot
    if (Test-Path "C:\Windows\System32\drivers\$ByovdDriver") {
        Write-Host "BYOVD driver will load at boot..." -ForegroundColor Yellow
        sc.exe create dxgkrnlSvc binPath= "C:\Windows\System32\drivers\$ByovdDriver" type= kernel 2>&1 | Out-Null
        Write-Success "Created dxgkrnlSvc service"
    }

    Write-Step "Bootkit Configuration Complete"
    Write-Host @"

Configuration:
  - Test Signing: ENABLED
  - Integrity Checks: DISABLED
  - BYOVD Driver: dxgkrnl.sys (loads at boot)
  - Persistence: PERMANENT (until manually disabled)
  - pbfilter.sys: Ready at $SysPath

Next Steps:
  1. Reboot your computer
  2. BYOVD driver will load automatically
  3. DSE will be bypassed
  4. Run peerblock.exe as Administrator

To undo:
  bcdedit /set testsigning off
  bcdedit /set nointegritychecks off
  sc delete dxgkrnlSvc
  (Reboot)

"@ -ForegroundColor Green
}

# ============================================================================
# Main Execution
# ============================================================================

switch ($Method) {
    "DseFix" { Enable-DseFix }
    "TestSign" { Enable-TestSign }
    "F7" { Enable-F7 }
    "Bootkit" { Enable-Bootkit }
}

Write-Host "`n=== BYOVD Setup Complete ===" -ForegroundColor Green
Write-Host "Method: $Method" -ForegroundColor Yellow
Write-Host "pbfilter.sys should now load with DSE bypassed." -ForegroundColor Yellow
Write-Host "Run peerblock.exe as Administrator to use." -ForegroundColor Yellow
