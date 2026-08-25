# PeerBlock for Windows 11 (security fork)

Fork of [PeerBlock/peerblock](https://github.com/PeerBlock/peerblock) (last upstream commit 2015).
This tree hardens the 2015 source, adds native IPv6 / CIDR lists, and loads
`pbfilter.sys` on Windows 11 with **test signing** (no F7 / driver-signature
enforcement off).

Upstream license is zlib (`license.txt`). This is **not** an official PeerBlock
release and is **not** Microsoft-signed. The `.sys` is **test-signed** on your
machine.

| Doc | What it covers |
|-----|----------------|
| [FEATURES.md](FEATURES.md) | Features added vs 2015 upstream |
| [SECURITY.md](SECURITY.md) | Every security patch (PB-01 … PB-21) |
| [WINDOWS11.md](WINDOWS11.md) | Build and test-sign steps |
| [doc/list-format.txt](doc/list-format.txt) | IPv4 CIDR and IPv6 list syntax |

## Features added (short)

- **Native IPv6 blocking** (upstream always allowed real IPv6)
- **IPv4 CIDR** and **IPv6 CIDR / bracket ranges** in `.p2p` lists
- P2B **cache v4** (IPv4 + IPv6); older caches still load
- **HTTPS-only** list updates (WinHTTP / Schannel); HTTP and `file://` rejected
- AllowLocal also allows **IPv6 link-local, ULA, loopback**, and adapter IPv6
- Optional **`BlockUnknownIPv6`** config key (default off)
- **Block HTTP** drops TCP 80, TCP 443, and UDP 443 (HTTP/3), not only IP lists
- ICMPv6 labeled in the live log
- Windows 10/11 recognized in the startup log

Details: [FEATURES.md](FEATURES.md). List examples: [doc/list-format.txt](doc/list-format.txt).

## Load `pbfilter.sys` on Windows 11

You do **not** need to disable driver signature enforcement (F7 / Advanced
startup). You need **test mode** plus a **test signature** on the `.sys`.

An unsigned driver still fails with error 577 even in test mode. The optional
`sign-pbfilter.cmd` next to `pbfilter.sys` does the signing.

### One-time setup

1. Build **Release_(Vista) | x64** (see [Build](#build)), or copy `peerblock.exe`
   and `pbfilter.sys` into the same folder.
2. **Turn off Memory integrity** if it is on:
   Settings → Privacy & security → Windows Security → Device security →
   Core isolation → Memory integrity → Off. Reboot if Windows asks.
3. Right-click `sign-pbfilter.cmd` (same folder as `pbfilter.sys`) →
   **Run as administrator**.
   - Trusts a local `CN=PeerBlock Test` certificate
   - Signs `pbfilter.sys`
   - Enables test signing (`bcdedit /set testsigning on`) if it is off
4. **Reboot once** if the script just turned test signing on (desktop may show
   a *Test Mode* watermark).
5. Run `peerblock.exe` **as Administrator**.

After that, starting PeerBlock does **not** require signing again. Rebuild
`pbfilter.sys` and re-run `sign-pbfilter.cmd`.

From a repo checkout you can also run:

```powershell
# Elevated PowerShell
bcdedit /set testsigning on
# Reboot once if that was not already Yes.

powershell -ExecutionPolicy Bypass -File build\windows\sign-pbfilter.ps1
```

`sign-pbfilter.ps1` looks for `pbfilter.sys` next to itself (or in the current
output folder when copied there by the driver build).

### What you do *not* need

- Advanced startup → F7 / “Disable driver signature enforcement”
- `bcdedit /set nointegritychecks on`
- A Microsoft Hardware Dev Center / WHQL signature (that is only for a
  stock machine with test signing off)

### Undo test mode

```powershell
bcdedit /set testsigning off
```

Reboot. `pbfilter.sys` will not load until you turn test signing back on or
replace it with a Microsoft-signed driver.

More detail and last-resort fallbacks: [WINDOWS11.md](WINDOWS11.md).

## What was patched (short)

- Kernel device ACL (Administrators / SYSTEM only) and exclusive open
- IOCTL integer overflow / pool-overflow checks, IRP cancel-safe queue, port-list races
- HTTPS list updates via WinHTTP/Schannel (old libcurl had **no TLS**)
- P2B parser bounds, zip-bomb caps, TinyXML DTD/ENTITY reject
- SQLite **3.53.4**, zlib **1.3.2**
- Native IPv6 range blocking + CIDR list syntax

Full table: [SECURITY.md](SECURITY.md).

## Build

Needs Visual Studio 2022 (C++ desktop or Build Tools) and the matching
**Windows Driver Kit** (kernel headers under
`Windows Kits\10\Include\<ver>\km`).

Open `build\windows\PeerBlock.sln`, configuration **Release_(Vista) | x64**.
After a driver build, `sign-pbfilter.cmd` is copied next to `pbfilter.sys`.

## Disclaimer

Use at your own risk. Test signing lets this PC load drivers signed with a
locally trusted test certificate. It is not a Microsoft-signed release and is
not a substitute for Hardware Dev Center attestation on other machines.
