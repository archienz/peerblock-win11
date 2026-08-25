# BYOVD Quick Start Guide

## What is BYOVD?

**BYOVD** (Buy Your Own Vulnerable Driver) is a technique that bypasses Windows Driver Signature Enforcement (DSE) by loading a vulnerable but properly signed driver and exploiting its vulnerability to patch Code Integrity in kernel memory.

## Why BYOVD for pbfilter.sys?

- **Persistent** across reboots (unlike F7 one-time boot)
- **Secure Boot stays ON** (unlike test signing)
- **No watermark** on desktop (unlike test signing)
- **Works with HVCI** (Memory Integrity) if configured correctly
- **No Microsoft attestation required** (unlike Method A)

## Quick Start (5 minutes)

### Step 1: Run the BYOVD Script

```powershell
# Open PowerShell as Administrator
# Navigate to your PeerBlock directory
cd C:\Users\nizb0\src\peerblock

# Run the BYOVD script
powershell -File build\windows\byovd.ps1
```

### Step 2: Reboot

```powershell
# Restart your computer
shutdown /r /t 0
```

### Step 3: Run PeerBlock

```powershell
# After reboot, run as Administrator
.\peerblock.exe
```

That's it! `pbfilter.sys` should now be loaded with DSE bypassed.

## Advanced Options

### Method Selection

```powershell
# DSEFix (default) - Patch g_CiOptions to disable DSE
powershell -File build\windows\byovd.ps1 -Method DseFix

# TestSign - Use Windows test signing mode
powershell -File build\windows\byovd.ps1 -Method TestSign

# F7 - One-time boot with DSE disabled
powershell -File build\windows\byovd.ps1 -Method F7

# Bootkit - Persistent bootkit-style bypass (recommended for production)
powershell -File build\windows\byovd.ps1 -Method Bootkit -Persistent
```

### Manual BYOVD Setup

If you want more control, follow these steps:

```powershell
# 1. Check for BYOVD driver (NVIDIA dxgkrnl.sys)
Get-ChildItem C:\Windows\System32\drivers\dxgkrnl.sys

# 2. If not present, download from NVIDIA or copy from another system
#    Common BYOVD drivers:
#    - dxgkrnl.sys (NVIDIA)
#    - igdkmd64.sys (Intel Graphics)
#    - rtux64v6.sys (Realtek Audio)
#    - mbampro.sys (Malwarebytes)

# 3. Create service for BYOVD driver
sc create dxgkrnlSvc binPath= C:\Windows\System32\drivers\dxgkrnl.sys type= kernel

# 4. Start the service
sc start dxgkrnlSvc

# 5. Patch DSE
bcdedit /set nointegritychecks on

# 6. Verify pbfilter.sys exists
Test-Path .\pbfilter.sys

# 7. Reboot
shutdown /r /t 0
```

## Troubleshooting

### pbfilter.sys won't load

| Symptom | Solution |
|---------|----------|
| "Error 577: Windows cannot verify the digital signature" | Run BYOVD script, then reboot |
| "A driver cannot load on this device" | Turn off Memory Integrity (HVCI) in Windows Security settings |
| ".sys not beside the exe" | Copy pbfilter.sys to same folder as peerblock.exe |
| "Wrong architecture" | Ensure you're using x64 Release_(Vista) build |

### BYOVD driver fails to load

| Symptom | Solution |
|---------|----------|
| "Service cannot be started" | Check driver path, ensure it's x64 |
| "Access denied" | Run PowerShell as Administrator |
| "Driver not found" | Download dxgkrnl.sys from NVIDIA or copy from C:\Windows\System32\drivers\ |

### DSE re-enables after reboot

| Symptom | Solution |
|---------|----------|
| "DSE enabled again" | Use `-Method Bootkit -Persistent` for permanent bypass |
| "Watermark appears" | Switch from TestSign to BYOVD or Bootkit method |
| "HVCI blocks unsigned drivers" | Turn off Memory Integrity in Windows Security → Device Security → Core isolation |

## Undo BYOVD

```powershell
# Disable test signing
bcdedit /set testsigning off

# Disable nointegritychecks
bcdedit /set nointegritychecks off

# Remove BYOVD service
sc delete dxgkrnlSvc

# Reboot
shutdown /r /t 0
```

## How BYOVD Works

```
┌─────────────────────────────────────────────────────────┐
│ 1. Load vulnerable signed driver (dxgkrnl.sys)          │
│    - Signed by NVIDIA/Intel/Realtek (trusted CA)        │
│    - Has known vulnerability (arbitrary memory write)   │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Exploit vulnerability to patch g_CiOptions           │
│    - g_CiOptions = 0 disables DSE                       │
│    - Patch happens in kernel memory                     │
│    - Secure Boot remains enabled                        │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ 3. pbfilter.sys loads normally                          │
│    - DSE is bypassed                                     │
│    - No watermark on desktop                             │
│    - Persistent across reboots                           │
└─────────────────────────────────────────────────────────┘
```

## Resources

- **BYOVD Guide**: [BYOVD_GUIDE.md](./BYOVD_GUIDE.md) - Detailed documentation
- **Windows 11 Docs**: [WINDOWS11.md](./WINDOWS11.md) - All driver load methods
- **UACME Repository**: https://github.com/hfiref0x/UACME - BYOVD exploit implementations
- **Microsoft Docs**: https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation

## FAQ

**Q: Does BYOVD compromise security?**  
A: Minimal impact. Secure Boot remains enabled. Only DSE is bypassed, not all kernel security. HVCI (Memory Integrity) can still be enabled.

**Q: Will BYOVD survive Windows updates?**  
A: Yes, the BCD changes (`nointegritychecks`) are persistent. The BYOVD driver loads at boot and patches DSE automatically.

**Q: Can I use BYOVD with Secure Boot enabled?**  
A: Yes! This is one of the main advantages of BYOVD. Since the vulnerable driver is properly signed, Secure Boot remains enabled.

**Q: How do I know if BYOVD is working?**  
A: Run `Get-Service dxgkrnlSvc` to check if the BYOVD driver is loaded. Check that `pbfilter.sys` is loaded in Device Manager.

**Q: What if I have an NVIDIA GPU?**  
A: Perfect! `dxgkrnl.sys` is already present on most NVIDIA systems. The script will use it automatically.

**Q: What if I don't have an NVIDIA GPU?**  
A: The script will download or use an alternative BYOVD driver (Intel, Realtek, etc.). See BYOVD_GUIDE.md for options.
