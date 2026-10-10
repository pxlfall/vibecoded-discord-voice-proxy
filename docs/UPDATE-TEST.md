# In-app update survival

Verified on 2026-10-10 in the Windows 11 ARM64 Parallels VM, running the
official x64 Discord client under emulation. Clash Verge SOCKS5 remained at
127.0.0.1:7897; its live TUN setting was false throughout the upgrade and
restart checks.

1. Backed up the previous Discord installation inside the VM.
2. Downloaded the older official **1.0.9253 x64** installer from Discord's CDN
   and verified its Authenticode signature. Installed it and stopped the first
   normal launch before it could update.
3. Applied the exact **v0.1 installer** published on GitHub. Verified both
   payload DLL hashes in `app-1.0.9253`. No source or binary changes were made.
4. Allowed Discord's normal updater to run. Its log recorded the host upgrade
   and relaunch from `app-1.0.9253` to `app-1.0.9261`.
5. Checked the new folder: `DWrite.dll`, `force-proxy.dll`, and `proxy.txt` all
   matched the older folder's SHA-256 hashes. The running 1.0.9261 processes
   loaded both patch DLLs from the new folder.
6. Confirmed a fresh gateway connection in the updated client's log. Fully
   stopped Discord and restarted it through its ordinary launcher:
   `Update.exe --processStart Discord.exe`. The new client connected again and
   still loaded the matching DLLs, with TUN off.

DLL SHA-256 values before and after the upgrade:

```text
DWrite.dll
06de5a104843c9b5d13b89efe81f37e522160ab19c186cca48d5de25beee5919

force-proxy.dll
e16f0f3c828f3220fbdf1b9a5a5367f4b22ebe65529378d39ceb8e658bcfbca6
```

The upstream loader's `CreateProcessW` hook copies those three proxy files
before Discord launches its executable in the new app folder. This mechanism
was retained in this fork, and the test required no patch reinstallation.

This establishes survival of the tested normal in-app upgrade. It does not
establish behavior for every future Discord updater or a clean reinstall.
Voice was tested before this upgrade; this follow-up checked file migration,
loaded DLLs, and gateway connectivity rather than joining another call.
