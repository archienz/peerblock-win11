# Running this fork on Windows 11

`pbfilter.sys` is a **kernel WFP callout**. Windows 11 will not load it on a
normal Home/Pro install because this tree is **not Microsoft-signed**.

You have three choices. Only (A) is a real public release. (B) and (C) are
local workarounds that reduce kernel security.

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

# After you have built pbfilter.sys:
powershell -File build\windows\testsign.ps1 -SysPath path\to\pbfilter.sys
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

## If the driver will not load

| Symptom | Cause |
|---------|--------|
| Windows cannot verify the digital signature / Error 577 / Code 52 | Enforcement is on and the `.sys` is not Microsoft-signed |
| A driver cannot load on this device | Memory integrity (HVCI) |
| Service start fails after F7 | Wrong architecture (need **x64** `Release_(Vista)`), or `.sys` not beside the exe |

## Build (x64 WFP)

1. Visual Studio 2022 with MSVC v143 and the Windows 11 **WDK** (kernel `km` headers).
2. `build\windows\PeerBlock.sln` → **Release_(Vista) | x64**.
3. Copy `peerblock.exe` and `pbfilter.sys` together. Run elevated.

`build\windows\props\wdk10.props` maps a standard Windows Kits 10 WDK install
onto the old `PB_DDK_DIR` include/lib layout. Spectre-mitigated CRT is used
only if those libs are present (default VS Build Tools often omit them).
The driver links `BufferOverflowK.lib` and uses `GsDriverEntry` for `/GS`.
