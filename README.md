# PeerBlock for Windows 11 (security fork)

Fork of [PeerBlock/peerblock](https://github.com/PeerBlock/peerblock) (last upstream commit 2015).
This tree hardens the 2015 source, adds native IPv6 / CIDR lists, and documents how to
**load the unsigned kernel driver on Windows 11**.

Upstream license is zlib (`license.txt`). This is **not** an official PeerBlock release
and is **not** Microsoft-signed.

| Doc | What it covers |
|-----|----------------|
| [FEATURES.md](FEATURES.md) | Features added vs 2015 upstream |
| [SECURITY.md](SECURITY.md) | Every security patch (PB-01 … PB-21) |
| [WINDOWS11.md](WINDOWS11.md) | Build, **driver signature enforcement**, test signing, attestation |
| [doc/list-format.txt](doc/list-format.txt) | IPv4 CIDR and IPv6 list syntax |

## Features added (short)

- **Native IPv6 blocking** (upstream always allowed real IPv6)
- **IPv4 CIDR** and **IPv6 CIDR / bracket ranges** in `.p2p` lists
- P2B **cache v4** (IPv4 + IPv6); older caches still load
- **HTTPS-only** list updates (WinHTTP / Schannel); HTTP and `file://` rejected
- AllowLocal also allows **IPv6 link-local, ULA, loopback**, and adapter IPv6
- Optional **`BlockUnknownIPv6`** config key (default off)
- ICMPv6 labeled in the live log
- Windows 10/11 recognized in the startup log

Details: [FEATURES.md](FEATURES.md). List examples: [doc/list-format.txt](doc/list-format.txt).

## Why the driver will not start on stock Windows 11

PeerBlock is not a user-mode firewall. Packet blocking is a **WFP callout kernel
driver** (`pbfilter.sys`). Starting with Windows 10 version 1607, a **new** kernel
driver will not load unless Microsoft signed it through Hardware Dev Center.

This fork does **not** ship a Microsoft-signed `.sys`. Until you get an EV
certificate and attestation (see WINDOWS11.md), you must either:

1. **Disable driver signature enforcement for this boot** (Advanced startup → F7), or
2. Enable **test signing** (`bcdedit /set testsigning on`) and sign the `.sys` with a test cert.

Both weaken kernel trust on that machine. They are a local-dev choice, not a
substitute for Hardware Dev Center signing.

## What was patched (short)

- Kernel device ACL (Administrators / SYSTEM only) and exclusive open
- IOCTL integer overflow / pool-overflow checks, IRP cancel-safe queue, port-list races
- HTTPS list updates via WinHTTP/Schannel (old libcurl had **no TLS**)
- P2B parser bounds, zip-bomb caps, TinyXML DTD/ENTITY reject
- SQLite **3.53.4**, zlib **1.3.2**
- Native IPv6 range blocking + CIDR list syntax

Full table: [SECURITY.md](SECURITY.md).

## Build

Needs Visual Studio 2022 (C++ desktop) and the matching **Windows Driver Kit**
(kernel headers live under `Windows Kits\10\Include\<ver>\km`).

Open `build\windows\PeerBlock.sln`, configuration **Release_(Vista) | x64**.

## Disclaimer

Use at your own risk. Disabling driver signature enforcement lets *any* unsigned
kernel driver load, not just PeerBlock.
