# v0.1 validation

Tested on 2026-10-10 with Discord 1.0.9261 x64 and Clash Verge SOCKS5 at
127.0.0.1:7897. TUN was disabled for the functional tests.

- In a Windows 11 ARM64 Parallels VM running x64 Discord under emulation,
  Windows DNS returned a poisoned address and unmodified Discord timed out.
- The patched installer launched Discord normally. Updates completed, the
  gateway connected, and the voice connection reached CONNECTED.
- The user confirmed that this exact installer also worked on their physical
  Windows x64 PC, including voice, with TUN disabled.
- Offline DNS parser tests passed on macOS and Windows. They cover compression,
  truncation, loops, question and transaction checks, CNAME chains, NXDOMAIN,
  SERVFAIL, and TTL limits.
- The live probe exercised narrow, wide, and legacy Winsock resolvers. An
  unreachable proxy and a nonexistent domain returned errors without falling
  back to system DNS.
- Both payload DLLs import Windows system DLLs only. The installer embeds the
  .NET 8 runtime and both DLLs.
- A cached-DNS stress test performed 100,000 sequential lookups and five
  rounds of 100,000 lookups across eight threads, with no failures or handle
  growth. Sequential private memory stayed constant. Parallel private memory
  remained between 11.1 and 11.3 MiB after initialization, rather than growing
  with each round. A real refresh after 310 seconds also succeeded. This tests
  resolver behavior, not whole-client CPU overhead.

The v0.1 installer is the same binary the user tested, SHA-256:

```text
26840e3bbfcd4c8ad588f4e48fa13bfc2654f595dae3c80436cc7211411f8ecc
```

This is functional validation of these setups. The interrupted performance
comparison does not establish a CPU-overhead figure, and a continuous
30-minute voice call was not verified.
