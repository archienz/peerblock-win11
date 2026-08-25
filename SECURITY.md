# Security audit (PeerBlock, last upstream commit 2015-05-24)

No CVE IDs were assigned to PeerBlock itself. The issues below are
vulnerability *classes* found in this tree and patched on the
`win11-security` branch.

## Patched in first-party code

| ID | Severity | Component | Issue | Fix |
|----|----------|-----------|-------|-----|
| PB-01 | Critical | `pbfilter` | `\\.\pbfilter` created with no ACL; any process could send IOCTLs (disable filtering, replace lists, pool overflow) | `IoCreateDeviceSecure` + exclusive handle, SDDL `SY`/`BA` only |
| PB-02 | Critical | `pbfilter` | `IOCTL_PEERBLOCK_SETRANGES` trusted `count` with wrapping `offsetof` / alloc size (kernel pool overflow) | `PbSafeULongMult` + `PB_MAX_RANGES` + size check before copy |
| PB-03 | High | `pbfilter` | Port-array swap raced with `bsearch` (use-after-free at DISPATCH) | Swap under spinlock; lookup holds the same lock |
| PB-04 | High | `pbfilter` | IRP cancel vs queue lock deadlock / completion race | Cancel-safe queue (`IoCsq*`) |
| PB-05 | High | `pbfilter` | Lookaside alloc not checked; NULL deref BSOD | Check alloc; cap queued notifications |
| PB-06 | High | `filter_wfp.c` | IPv6 `byteArray16` NULL deref BSOD | NULL check; continue |
| PB-07 | High | `filter_wfp.c` | `block==0` returned from classify without an action | Always set CONTINUE or BLOCK |
| PB-08 | High | updates | libcurl **7.22.0 with no TLS backend**; all list/program fetches were cleartext HTTP (MITM can replace blocklists) | WinHTTP + Schannel, HTTPS-only, TLS 1.2+, no HTTPS→HTTP redirects, 64 MiB cap |
| PB-09 | High | `list_p2b.cpp` | P2B v3 used attacker `name` index with no bounds check (OOB `wstring`) | Cap counts; `name < namecount` |
| PB-10 | Medium | zip/gzip/7z | Unbounded decompress (zip bomb) from downloaded lists | 64 MiB cap |
| PB-11 | Medium | `utf8.h` | UTF-8 decoder walked past end of buffer | Remaining-byte checks + continuation validation |
| PB-12 | Medium | history SQL | Date strings concatenated into SQL | Bound parameters |
| PB-13 | Medium | `filter.c` | TCP header parsed without length check | Require `len >= sizeof(TCP_HEADER)` |
| PB-14 | Low | ports IOCTL | `USHORT` truncation of port-list length | Exact size validation |
| PB-15 | Low | cleanup | Queue destroyed while WFP callouts still running | Reset on close; destroy after unregister on unload |

| PB-16 | High | sqlite | 3.8.10.2 amalgamation, years of CVEs | Replaced with **3.53.4** |
| PB-17 | Medium | zlib | 1.2.8 (CVE-2016-9840..9843 and later) | Replaced with **1.3.2** |
| PB-18 | Medium | TinyXML | DTD/ENTITY in config XML | Reject `<!` other than comment/CDATA |
| PB-19 | Medium | UI/lists | http/file/ftp list URLs | HTTPS-only add; rewrite on load |
| PB-20 | Low | SOCKS5 | WinHTTP would silently go direct | Fail closed with an error |
| PB-21 | High | WFP IPv6 | Native IPv6 never matched a list | `IOCTL_PEERBLOCK_SETRANGES6` + classify |

## Remaining

- **Driver signature (Win11 blocker).** See `WINDOWS11.md`.
- **libcurl 7.22.0** is still in the tree but is no longer used for downloads.
- **LZMA SDK 9.20** still used for `.7z` lists.
- **User-mode label pointers** in IOCTL range structs (device is exclusive).
- SOCKS5 update proxies are unsupported (HTTP proxy or direct).

## Threat model after patches

- Local non-admin: cannot open the filter device, cannot flip block state.
- Local admin: can still load/unload the service (by design; the app is
  `requireAdministrator`).
- Network MITM: list updates refuse HTTP; TLS uses the Windows certificate
  store.
- Malicious list file: P2B OOB and zip bombs are rejected; remaining parser
  is range insertion only.

New list syntax (IPv4 CIDR, IPv6 `[addr]-[addr]` / `[addr]/prefix`) is
documented in `doc/list-format.txt`. Optional config `BlockUnknownIPv6`
blocks IPv6 that is not on an allow or block list (default off).
