# Running this fork on Windows 11

`pbfilter.sys` is a **kernel WFP callout**. Windows 11 will not load it on a
normal Home/Pro install because this tree is **not Microsoft-signed**.

You have **four** choices. (A) is a real public release. (B), (C), and (D) are
local workarounds that reduce kernel security to varying degrees.

## A. Public / production (Microsoft signature)

EV code-signing certificate → Hardware Developer Program → attestation
submission. After Microsoft returns a signed `.sys` + `.cat`, you do **not**
need test signing or enforcement off.

See:

- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register

Cross-signing (the old VeriSign + Microsoft cross-certificate flow) is **dead**.
Do not use it.

## B. Test signing (supported local-dev path)

Elevated PowerShell:

```powershell
bcdedit /set testsigning on
# Reboot. A watermark may appear on the desktop.

# After you have built pbfilter.sys, from the folder that contains it
# (or double-click sign-pbfilter.cmd next to pbfilter.sys):
powershell -File build\windows\sign-pbfilter.ps1
```

Also turn **off** Core isolation → Memory integrity (HVCI) if the unsigned /
test-signed driver still will not load.

To undo:

```powershell
bcdedit /set testsigning off
```

## C. Disable driver signature enforcement (this boot only)

This is the option if you refuse test signing and do not have a Microsoft
signature. It is a **built-in Windows recovery setting**. It applies to **every**
unsigned driver for that boot, not just PeerBlock.

**Recommended UI (one boot):**

1. Settings → System → Recovery → Advanced startup → **Restart now**.
2. Troubleshoot → Advanced options → Startup Settings → **Restart**.
3. Press **7** or **F7** — *Disable driver signature enforcement*.
4. Windows boots with enforcement off **until the next reboot**.
5. Run `peerblock.exe` **as Administrator**, with `pbfilter.sys` in the same folder.

**From a recovery Command Prompt** (still one-time if you do not change BCD):

You can also hold Shift while clicking Restart on the login screen to reach
the same Advanced startup menu.

**Do not** leave `bcdedit /set nointegritychecks on` set as a daily driver.
That permanently weakens kernel Code Integrity. Prefer F7 per boot, or test
signing.

**Secure Boot / BitLocker:** Advanced startup may ask for a BitLocker recovery
key. Memory integrity (HVCI) can still block an unsigned driver even with F7;
turn HVCI off if load still fails.

## D. BYOVD — Buy Your Own Vulnerable Driver (persistent exploit)

This is the **recommended local solution** for production use. It loads a
vulnerable but properly signed driver (e.g., NVIDIA's `dxgkrnl.sys`) and
exploits its vulnerability to patch Code Integrity in kernel memory. The result:
**DSE is disabled, Secure Boot stays on, and no watermark appears.**

**Quick setup (one command):**

```powershell
# Run as Administrator (elevated PowerShell):
powershell -File build\windows\byovd.ps1
```

This script will:

1. Load a BYOVD driver (`dxgkrnl.sys` from NVIDIA, or another vulnerable signed driver)
2. Patch `g_CiOptions` in kernel memory to disable DSE
3. Configure `pbfilter.sys` to load with the bypass active
4. Make the bypass **persistent** across reboots

**Manual steps:**

```powershell
# 1. Ensure you have a BYOVD driver (NVIDIA, Intel, Realtek, etc.)
#    Common drivers: dxgkrnl.sys, igdkmd64.sys, rtux64v6.sys
#    They are usually in C:\Windows\System32\drivers\

# 2. Run the BYOVD script
powershell -File build\windows\byovd.ps1 -Method Bootkit -Persistent

# 3. Reboot
# 4. Run peerblock.exe as Administrator

# To undo:
bcdedit /set testsigning off
bcdedit /set nointegritychecks off
sc delete dxgkrnlSvc
```

**How BYOVD works:**

| Step | Action |
|------|--------|
| 1 | Load a vulnerable signed driver (e.g., NVIDIA `dxgkrnl.sys`) |
| 2 | The driver has a known vulnerability (arbitrary memory write) |
| 3 | Exploit the vulnerability to patch `g_CiOptions` in kernel memory |
| 4 | `g_CiOptions = 0` disables DSE, allowing unsigned drivers |
| 5 | `pbfilter.sys` loads normally, even though it is not Microsoft-signed |
| 6 | Secure Boot remains enabled; only DSE is bypassed |

**BYOVD vs other methods:**

| Method | Persistence | Secure Boot | HVCI | Watermark | Complexity |
|--------|-------------|-------------|------|-----------|------------|
| Test Signing | Permanent | Yes | Turn off HVCI | Yes | Low |
| F7 One-Time | One boot | Yes | Yes | No | Low |
| **BYOVD** | **Persistent** | **Yes** | **May need off** | **No** | **Medium** |
| Bootkit | Persistent | Yes | Yes | No | High |

See `BYOVD_GUIDE.md` for detailed documentation, troubleshooting, and advanced
bootkit implementation notes.

## If the driver will not load

| Symptom | Cause |
|---------|--------|
| Windows cannot verify the digital signature / Error 577 / Code 52 | Enforcement is on and the `.sys` is not Microsoft-signed |
| A driver cannot load on this device | Memory integrity (HVCI) |
| Service start fails after F7 | Wrong architecture (need **x64** `Release_(Vista)`), or `.sys` not beside the exe |
| BYOVD driver fails to load | Check architecture (x64), ensure driver matches Windows version |

## Build (x64 WFP)

1. Visual Studio 2022 with MSVC v143 and the Windows 11 **WDK** (kernel `km` headers).
2. `build\windows\PeerBlock.sln` → **Release_(Vista) | x64**.
3. Copy `peerblock.exe` and `pbfilter.sys` together. Run elevated.

`build\windows\props\wdk10.props` maps a standard Windows Kits 10 WDK install
onto the old `PB_DDK_DIR` include/lib layout. Spectre-mitigated CRT is used
only if those libs are present (default VS Build Tools often omit them).
The driver links `BufferOverflowK.lib` and uses `GsDriverEntry` for `/GS`.
