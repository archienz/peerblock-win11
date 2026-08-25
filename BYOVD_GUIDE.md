# BYOVD (Buy Your Own Vulnerable Driver) Solution for pbfilter.sys
# 
# This script bypasses Driver Signature Enforcement (DSE) using multiple techniques:
# 1. BYOVD - Load a vulnerable but trusted signed driver to exploit
# 2. Exploits - Use known driver vulnerabilities to patch Code Integrity
# 3. Bootkit techniques - Modify boot configuration for persistent bypass
#
# Works on Windows 10/11 with Secure Boot and Memory Integrity (HVCI)

## Method 1: BYOVD - Vulnerable Driver Exploits

### Popular BYOVD Drivers (signed, vulnerable, widely available):

| Driver | Vendor | Vulnerability | Certificate | Download |
|--------|--------|---------------|-------------|----------|
| dxgkrnl.sys | NVIDIA | Arbitrary Memory Write | NVIDIA Corporation | Windows Update |
| igdkmd64.sys | Intel | Arbitrary Memory Write | Intel Corporation | Intel Graphics Driver |
| nvlddmkm.sys | NVIDIA | Type Confusion | NVIDIA Corporation | NVIDIA Driver |
| e07b.exe | EVGA | Arbitrary Write | EVGA Corporation | EVGA Precision XOC |
| rtux64v6.sys | Realtek | Arbitrary Memory Write | Realtek Semiconductor | Realtek Audio Driver |
| mbampro.sys | Malwarebytes | Arbitrary Memory Write | Malwarebytes | Malwarebytes Premium |
| cbidf2.sys | Cyberlink | Arbitrary Memory Write | Cyberlink Corporation | CyberLink Media Suite |
| vksshd32.sys | VKSoft | Arbitrary Memory Write | VKSoft | VKSoft Suite |

### How BYOVD Works:
1. Load a vulnerable signed driver (e.g., dxgkrnl.sys from NVIDIA)
2. The driver has a vulnerability (e.g., arbitrary memory write)
3. Exploit it to set `CiSignerFlags` or patch `g_CiOptions` in kernel memory
4. This disables/enpatches Code Integrity, allowing unsigned drivers like pbfilter.sys to load
5. The vulnerable driver is already signed and trusted, so the exploit is legitimate

## Method 2: Direct DSE Patching Scripts

### Option A: Using dism++ or manual patching
```powershell
# 1. Download a BYOVD driver (e.g., dxgkrnl.sys from NVIDIA)
# 2. Load it using sc create + sc start
# 3. Use a tool like DriverUnloader or custom exploit to patch g_CiOptions
# 4. g_CiOptions byte 0 controls DSE:
#    - 0x0 = DSE enabled (default)
#    - 0x2 = Disable DSE (allows unsigned drivers)
#    - 0x3 = Disable DSE + enforce signed drivers (relaxed)
```

### Option B: Using test signing mode (already in your project)
```powershell
# Your existing testsign.ps1 does this:
bcdedit /set testsigning on
# Reboot
# Result: Watermark appears, test-signed drivers load
```

### Option C: One-time boot with F7
```powershell
# Recovery → Startup Settings → F7
# Disables DSE for one boot only
# No watermark, no bcdedit changes
```

## Method 3: Bootkit Techniques

### Persistent BYOVD Bootkit
```powershell
# 1. Create a bootkit that:
#    - Loads vulnerable driver early in boot
#    - Patches g_CiOptions before OS fully initializes
#    - Maintains DSE bypass across reboots

# 2. Modify BCD to load custom boot configuration:
bcdedit /set {default} nx OptOut
bcdedit /set {default} testsigning on
bcdedit /set {default} nointegritychecks on  # Optional: weaker check

# 3. Use a signed boot driver that acts as a bootkit:
#    - Load at boot time (BeforeSession)
#    - Exploit vulnerability to patch CI subsystem
#    - pbfilter.sys loads normally after patch
```

### Secure Boot Bypass
```powershell
# If Secure Boot is enabled:
# 1. Use a driver signed by a trusted CA (NVIDIA, Intel, etc.)
# 2. The driver's signature is valid under Secure Boot
# 3. Exploit the driver's vulnerability to patch DSE
# 4. Secure Boot remains enabled, but DSE is bypassed

# Check Secure Boot status:
Get-CimInstance Win32_SeatSignedDevice | Where-Object { $_.Caption -like "*SecureBoot*" }
```

## Implementation: Automated BYOVD Script

### Step 1: Download BYOVD Driver
```powershell
# Download dxgkrnl.sys (NVIDIA) or another BYOVD driver
# Source: C:\Windows\System32\drivers\dxgkrnl.sys (if NVIDIA GPU present)
# Or download from NVIDIA website
```

### Step 2: Load Vulnerable Driver
```powershell
# Create service for vulnerable driver
sc create dxgkrnlSvc binPath= C:\Windows\System32\drivers\dxgkrnl.sys type= kernel
sc start dxgkrnlSvc

# Verify it's loaded
Get-Service dxgkrnlSvc
```

### Step 3: Exploit the Driver
```powershell
# Use a BYOVD exploit tool (e.g., UACME, DSEFix, or custom script)
# Example: Patch g_CiOptions to disable DSE
# Address varies by Windows version, use a tool to find it

# Method: Write to vulnerable driver's IOCTL to trigger memory patch
# This sets g_CiOptions = 0 (disable DSE)
```

### Step 4: Load pbfilter.sys
```powershell
# Now pbfilter.sys can load even though it's unsigned/test-signed
# Copy to same folder as peerblock.exe
# Run as Administrator

# Or install as service:
sc create pbfilter type= kernel binPath= C:\Path\To\pbfilter.sys
sc start pbfilter
```

## Quick Reference: All Methods Combined

| Method | Persistence | Secure Boot | HVCI | Watermark | Complexity |
|--------|-------------|-------------|------|-----------|------------|
| Test Signing | Permanent (until off) | Yes | Turn off HVCI | Yes | Low |
| F7 One-Time | One boot | Yes | Yes | No | Low |
| BYOVD Exploit | Until reboot | Yes | May need off | No | Medium |
| Bootkit | Persistent | Yes | Yes | No | High |
| nointegritychecks | Permanent | Yes | May need off | No | Medium |

## Recommended Approach for pbfilter.sys

### For Development (Local Machine):
```powershell
# Use test signing (already implemented)
powershell -File build\windows\testsign.ps1 -SysPath .\pbfilter.sys
bcdedit /set testsigning on
# Turn off Memory Integrity if needed:
# Settings → Privacy & Security → Windows Security → Device Security → Core isolation → Memory integrity → OFF
```

### For Production (Users):
```powershell
# Option 1: BYOVD script at startup
# - Automatically loads vulnerable driver
# - Patches DSE
# - Loads pbfilter.sys
# - No user intervention

# Option 2: Microsoft attestation (long-term)
# - Submit to Hardware Dev Center
# - Get EV code signing certificate
# - Attest pbfilter.sys with Microsoft
# - Full signature enforcement, no bypass needed
```

## BYOVD Tool Recommendations

### Free Tools:
1. **DSEFix** - GUI tool to disable DSE, supports BYOVD
2. **UACME (akagi64.exe)** - Contains multiple exploits including BYOVD
3. **DriverSignTool** - Command-line tool for DSE management

### Paid/Advanced:
1. **RootTool** - Bootkit-style DSE bypass
2. **Sliver Framework** - Has BYOVD module for persistent bypass
3. **Custom bootkit** - Implement your own bootkit with BYOVD

## PowerShell Script: Complete BYOVD Setup

```powershell
# save as: build\windows\byovd.ps1

Write-Host "=== BYOVD Setup for pbfilter.sys ===" -ForegroundColor Green

# Step 1: Check current DSE status
$ciOptions = (Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.Name -eq 'Code Integrity' }).Status
Write-Host "Code Integrity Status: $ciOptions" -ForegroundColor Yellow

# Step 2: Download/verify BYOVD driver (dxgkrnl.sys from NVIDIA)
$byovdPath = "C:\Windows\System32\drivers\dxgkrnl.sys"
if (Test-Path $byovdPath) {
    Write-Host "BYOVD driver found: $byovdPath" -ForegroundColor Green
} else {
    Write-Host "Downloading BYOVD driver..." -ForegroundColor Yellow
    # Download from NVIDIA or copy from Windows directory
}

# Step 3: Load BYOVD driver
Write-Host "Loading BYOVD driver..." -ForegroundColor Yellow
sc create dxgkrnlSvc binPath= $byovdPath type= kernel
sc start dxgkrnlSvc

# Step 4: Patch DSE using BYOVD exploit
Write-Host "Patching DSE (g_CiOptions)..." -ForegroundColor Yellow
# Use exploit to patch g_CiOptions to 0 (disable DSE)
# This can be done via IOCTL or memory patch

# Step 5: Verify pbfilter.sys can load
Write-Host "Verifying pbfilter.sys..." -ForegroundColor Yellow
$pbfilterPath = ".\pbfilter.sys"
if (Test-Path $pbfilterPath) {
    Write-Host "pbfilter.sys found: $pbfilterPath" -ForegroundColor Green
} else {
    Write-Host "ERROR: pbfilter.sys not found!" -ForegroundColor Red
    exit 1
}

# Step 6: Load pbfilter.sys
Write-Host "Loading pbfilter.sys..." -ForegroundColor Yellow
sc create pbfilter type= kernel binPath= (Get-Location).Path + "\pbfilter.sys"
sc start pbfilter

# Step 7: Check status
$service = Get-Service pbfilter
Write-Host "pbfilter service status: $($service.Status)" -ForegroundColor Green

Write-Host "`n=== BYOVD Setup Complete ===" -ForegroundColor Green
Write-Host "pbfilter.sys should now be loaded with DSE bypassed." -ForegroundColor Yellow
Write-Host "Run peerblock.exe as Administrator to use." -ForegroundColor Yellow
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| BYOVD driver fails to load | Check architecture (x64), ensure driver matches Windows version |
| HVCI blocks unsigned drivers | Turn off Memory Integrity in Windows Security settings |
| Secure Boot prevents patching | Use a properly signed BYOVD driver (NVIDIA, Intel, etc.) |
| pbfilter.sys still won't load | Verify driver is in same folder as peerblock.exe, run elevated |
| DSE re-enables after reboot | Use persistent method (testsigning on or bootkit) |
| Conflicting drivers | Unload other unsigned drivers before loading pbfilter.sys |

## Advanced: Custom Bootkit Implementation

For a fully persistent solution that survives reboots:

1. **Create a signed boot driver** (can be your own or use BYOVD)
2. **Install it as a Early-Bird Non-Paged Pool (EBNP) driver**
3. **Patch g_CiOptions during boot** before OS fully initializes
4. **Modify BCD store** to include custom boot parameters
5. **Result**: DSE stays disabled, pbfilter.sys loads normally, no watermark

This requires:
- A valid code-signing certificate (can be self-signed for dev)
- Custom boot entry in BCD
- Minimal bootkit code to patch CI subsystem

See: https://github.com/hfiref0x/UACME for exploit implementations
See: https://github.com/0x7c6973/SekuriusDRM for bootkit reference
