# Running this fork on Windows 11

`pbfilter.sys` is a **kernel WFP callout**. This tree is **not Microsoft-signed**.
You do **not** need to disable driver signature enforcement (F7). Use **test
signing** plus `sign-pbfilter.cmd` next to the `.sys`.

## A. Public / production (Microsoft signature)

EV code-signing certificate → Hardware Developer Program → attestation
submission. After Microsoft returns a signed `.sys` + `.cat`, you do **not**
need test signing or enforcement off.

See:

- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register

Cross-signing (the old VeriSign + Microsoft cross-certificate flow) is **dead**.
Do not use it.

## B. Test signing (use this)

Test mode still requires a **signature on the file**. `sign-pbfilter.cmd`
creates a local `CN=PeerBlock Test` cert, trusts it, and signs `pbfilter.sys`.
You do not turn off driver signature enforcement.

1. Turn **off** Memory integrity if it is on (Core isolation). Reboot if asked.
2. Run **`sign-pbfilter.cmd` as Administrator** from the folder that contains
   `pbfilter.sys` (the driver build copies the script there).
3. Reboot **once** if the script enabled test signing (`bcdedit /set testsigning on`).
   A *Test Mode* watermark may appear.
4. Run `peerblock.exe` as Administrator.

Rebuild the `.sys` → run `sign-pbfilter.cmd` again. Starting the app later does
not require re-signing.

From a checkout:

```powershell
bcdedit /set testsigning on
# Reboot if that was not already Yes.
powershell -ExecutionPolicy Bypass -File build\windows\sign-pbfilter.ps1
```

To undo:

```powershell
bcdedit /set testsigning off
```

## If the driver will not load

| Symptom | Cause |
|---------|--------|
| Windows cannot verify the digital signature / Error 577 / Code 52 | The `.sys` is unsigned, or test signing is off. Run `sign-pbfilter.cmd` as admin and reboot if test mode was just enabled. |
| A driver cannot load on this device | Memory integrity (HVCI) |
| Service start fails | Wrong architecture (need **x64** `Release_(Vista)`), or `.sys` not beside the exe |

## Build (x64 WFP)

1. Visual Studio 2022 with MSVC v143 and the Windows 11 **WDK** (kernel `km` headers).
2. `build\windows\PeerBlock.sln` → **Release_(Vista) | x64**.
3. Copy `peerblock.exe` and `pbfilter.sys` together. Run elevated.

`build\windows\props\wdk10.props` maps a standard Windows Kits 10 WDK install
onto the old `PB_DDK_DIR` include/lib layout. Spectre-mitigated CRT is used
only if those libs are present (default VS Build Tools often omit them).
The driver links `BufferOverflowK.lib` and uses `GsDriverEntry` for `/GS`.
