# Features added in this fork

Upstream PeerBlock (2015) blocked **IPv4 only** (plus a Teredo/6to4 hack) and
downloaded lists over **cleartext HTTP**. This fork adds the following
user-visible and driver-visible features on top of that.

## Filtering

| Feature | Upstream | This fork |
|---------|----------|-----------|
| IPv4 range lists (`a.b.c.d-e.f.g.h`) | Yes | Yes |
| IPv4 **CIDR** (`10.0.0.0/8`) | No | Yes |
| **Native IPv6** range lists | No (always allowed) | Yes — `IOCTL_PEERBLOCK_SETRANGES6` |
| IPv6 CIDR (`[2001:db8::]/32`) | No | Yes |
| IPv6 hyphen ranges (`[addr]-[addr]`) | No | Yes |
| Teredo / 6to4 mapped IPv4 | Yes | Yes, after native IPv6 match |
| Allow-list checked before block-list (v4 and v6) | v4 only | v4 and v6 |
| **Block unknown IPv6** (`BlockUnknownIPv6` in config) | n/a | Optional; default **off** |
| Allow local adapters | IPv4 only | IPv4 + IPv6 unicast/DNS |
| Well-known local IPv6 when AllowLocal is on | No | `fe80::/10`, `fc00::/7`, `::1` |

List syntax examples: [doc/list-format.txt](doc/list-format.txt).

Enable “block IPv6 that is not on any list” by adding this to the settings XML
(there is no extra checkbox yet):

```xml
<BlockUnknownIPv6>true</BlockUnknownIPv6>
```

## Lists and updates

| Feature | Upstream | This fork |
|---------|----------|-----------|
| List download protocol | HTTP (libcurl 7.22, **no TLS**) | **HTTPS only** (WinHTTP + Windows Schannel, TLS 1.2+) |
| HTTP → HTTPS rewrite | No | Yes, on load and at download time |
| Reject `file://` / `ftp://` / `http://` when adding a URL | No | Yes |
| HTTPS → HTTP redirect | Allowed | Refused |
| Download size cap | None | 64 MiB |
| SOCKS5 update proxy | Attempted via curl | **Not supported** (fails instead of going direct) |
| HTTP proxy | Yes | Yes |
| P2B cache | v1–v3 (IPv4) | **v4** stores IPv4 + IPv6; old files still load |
| iblocklist preset URLs | `http://` | `https://` |

## UI / logging

| Feature | Notes |
|---------|--------|
| Windows 10 / 11 in the log | `CheckOS()` no longer prints `UNKNOWN OS 10.0` |
| Live log IPv6 addresses | Already used `WSAAddressToString`; still works with native v6 blocks |
| ICMPv6 protocol label | Shown as `ICMPv6` instead of `Unknown` |

History database still stores IPv4 integers only. IPv6 hits appear in the
**live log**, not in the archived history.db rows.

## Windows 11 / build

| Feature | Notes |
|---------|--------|
| Compatibility manifest | Windows 10 GUID (covers 11) |
| VS 2015–2022 toolsets | `platform.props` maps v140–v143 |
| INF starter | `src/pbfilter/pbfilter.inf` |
| Test-sign helper | `sign-pbfilter.cmd` / `sign-pbfilter.ps1` next to `pbfilter.sys` |
| Driver load docs | [WINDOWS11.md](WINDOWS11.md) — **test signing** (no F7 required) |

## Not added

- Microsoft-signed `pbfilter.sys` (local use is test signing; attestation is only for stock PCs)
- SOCKS5 list updates
- Native IPv6 in `history.db`
- Settings UI checkbox for `BlockUnknownIPv6` (config key only)
- Full WHQL / Hardware Dev Center submission
