# Vibecoded Discord Voice Proxy

**Heavy vibecoded shit. Surprisingly, it works on my machine.**

A personal fork of [runetfreedom/discord-voice-proxy](https://github.com/runetfreedom/discord-voice-proxy), with [runetfreedom/force-proxy](https://github.com/runetfreedom/force-proxy) bundled into the same repository. All credit for the original loader and SOCKS5 wrapper goes to the upstream authors. This fork adds the DNS fix needed to get Discord working with Clash Verge when TUN mode is off.

The code was heavily written and debugged with an AI coding assistant, then tested in a Windows VM and on a physical Windows x64 PC. It is a personal experiment, not a polished networking product.

## Download and install

1. Download **DiscordProxyInstaller-v0.1-win-x64.exe** from [Release v0.1](https://github.com/pxlfall/vibecoded-discord-voice-proxy/releases/tag/v0.1).
2. Install the official **x64 Discord** client. This release does not support native ARM64 Discord.
3. Start Clash Verge with SOCKS5 listening at **127.0.0.1:7897**. Your selected outbound must support UDP for voice, and Clash must resolve SOCKS5 hostname requests through trusted DNS.
4. Run the installer as your normal Windows user. Accept the Clash Verge prompt. Discord restarts automatically.
5. Leave Clash running. TUN can remain off.

The installer includes the .NET runtime and both proxy DLLs. The v0.1 executable is the exact build tested successfully on the maintainer's main PC; it is unsigned.

Already using the original project? The installer backs up existing `DWrite.dll`, `force-proxy.dll`, and `proxy.txt` in `discord-proxy-backup`. Run this installer again and answer **Y** to the uninstall prompt to remove this installation and restore that backup.

## Why this exists

With TUN enabled, Clash can intercept DNS and send it through the proxy. With TUN disabled, Discord can ask Windows for an address, receive a poisoned DNS answer, and connect through the proxy to the wrong IP. That produces the eternal loading screen even though the proxy itself works.

Discord has more than one DNS path, so this fork handles both:

- **Winsock resolvers:** `getaddrinfo`, `GetAddrInfoW`, and `gethostbyname` obtain IPv4 answers from Cloudflare's `https://1.1.1.1/dns-query` through SOCKS5. The literal IP avoids a system-DNS bootstrap. TLS certificate validation remains enabled. Failed requests return an error without falling back to Windows DNS.
- **Discord's Chromium browser:** the loader supplies its SOCKS5 setting during normal startup, so Chromium forwards destination hostnames to Clash instead of resolving them locally. This path uses Clash's DNS configuration.

Successful DoH answers are cached for their DNS TTL, capped at five minutes. The cache holds at most 256 names per process. The added resolver has no background polling loop.

## Settings and diagnostics

The installer writes `proxy.txt` beside `Discord.exe`. The Clash preset is:

```ini
SOCKS5_PROXY_ADDRESS=127.0.0.1
SOCKS5_PROXY_PORT=7897
SOCKS5_PROXY_DNS=1
SOCKS5_DNS_LOG=1
```

The installer also supports entering a different numeric IPv4 proxy address, port, and optional SOCKS5 credentials.

DNS diagnostics are written to `%LOCALAPPDATA%\DiscordProxy\dns.log`. They contain requested domains, returned addresses, and errors. To disable logging, change `SOCKS5_DNS_LOG=0` in `proxy.txt`, then fully quit and restart Discord. To disable this fork's added DNS/browser handling, use `SOCKS5_PROXY_DNS=0`; the original socket proxy remains enabled.

## What has been tested

Discord 1.0.9261 x64 started, completed updates, connected to the gateway, and joined voice with TUN off. This worked in a Windows 11 ARM64 Parallels VM running the x64 client under emulation, and the maintainer confirmed the same executable worked on their physical Windows x64 PC.

The DNS parser and live resolver probes were also tested. See [validation details](docs/VALIDATION.md). Longer-term stability and a precise CPU-overhead comparison have not been established.

## Limitations

- Windows x64 payload only; IPv4 sockets only, inherited from the upstream wrapper.
- SOCKS5 UDP support is required for voice.
- Discord updates may replace the application folder and require reinstalling the patch.
- The original transport hooks remain largely unchanged. This is not a complete rewrite or audit of their asynchronous socket handling.
- Cloudflare DoH is hardcoded for this personal setup.

## Build and credits

Everything needed for this project's source build is in this repository: loader, installer, general wrapper, and tests. Follow [BUILD.md](BUILD.md); use CMake rather than the retained upstream Visual Studio solution files.

See [UPSTREAM.md](UPSTREAM.md) for original revisions and attribution. Original project documentation is preserved in [docs/UPSTREAM-README.md](docs/UPSTREAM-README.md) and [force-proxy/README.md](force-proxy/README.md).

GPL-3.0, as with the upstream projects. Dependency notices are under [licenses/](licenses/).
