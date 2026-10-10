# Building from this single repository

The Discord loader, installer, and general SOCKS5 wrapper are included here.
No sibling checkout or Git submodule is required. Build on Windows with Visual
Studio 2022 C++ tools, the Windows SDK, CMake, vcpkg, and the .NET 8 SDK.

From a Visual Studio developer PowerShell:

```powershell
./scripts/build.ps1 -VcpkgRoot C:/path/to/vcpkg
```

This builds x64 Release DLLs, runs the DNS parser tests, and publishes a
self-contained installer into `dist/DiscordProxyInstaller.exe`. The static
vcpkg triplet avoids requiring separate libcurl or Detours DLLs. Dependency
versions are selected by the baseline in `vcpkg.json`.

For live resolver checks, run `build/payload/Release/proxy_dns_probe.exe
discord.com` from its own directory while Clash listens at `127.0.0.1:7897`.
The probe covers narrow, wide, and legacy Winsock resolvers and proxied TCP.
Set `SOCKS5_PROXY_PORT=1` to test an unreachable proxy. DNS failures must return
an error, without falling back to Windows DNS.

`dns_perf_test.exe` measures repeated cached lookups and memory/handle usage.
Set `DNS_PERF_WAIT_TTL=1` to include a refresh after 310 seconds. These live
tests need a working proxy; they are separate from the offline parser tests.

The original `.sln` files are retained for upstream reference. Use CMake to
include the DNS and browser-proxy changes.
