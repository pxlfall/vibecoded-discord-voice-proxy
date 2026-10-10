#include <windows.h>
#include <detours/detours.h>
#include <algorithm>
#include <cstdlib>
#include <string>
#include "browser_proxy.h"

namespace {
decltype(&GetCommandLineW) Real_GetCommandLineW = GetCommandLineW;
decltype(&GetCommandLineA) Real_GetCommandLineA = GetCommandLineA;
std::wstring commandW;
std::string commandA;
LPWSTR WINAPI ProxyCommandLineW() { return commandW.data(); }
LPSTR WINAPI ProxyCommandLineA() { return commandA.data(); }
bool attached = false;
}

void AttachBrowserProxy() {
    // Chromium forwards proxy configuration to its child processes itself.
    // In particular, crashpad-handler is not a Chromium command-line parser.
    const std::wstring original = Real_GetCommandLineW();
    if (original.find(L"--type=") != std::wstring::npos) return;
    char enabled[8] = {};
    GetEnvironmentVariableA("SOCKS5_PROXY_DNS", enabled, sizeof(enabled));
    if (std::string(enabled) == "0") return;
    char address[64] = {}, port[16] = {};
    GetEnvironmentVariableA("SOCKS5_PROXY_ADDRESS", address, sizeof(address));
    GetEnvironmentVariableA("SOCKS5_PROXY_PORT", port, sizeof(port));
    const std::string host(address), service(port);
    if (host.empty() || service.empty() ||
        !std::all_of(host.begin(),host.end(),[](char c) { return (c >= '0' && c <= '9') || c == '.'; }) ||
        !std::all_of(service.begin(),service.end(),[](char c) { return c >= '0' && c <= '9'; })) return;
    const auto number = std::strtoul(port,nullptr,10);
    if (number == 0 || number > 65535) return;
    // Chromium sends its own DNS packets instead of using Winsock's resolver.
    // Forward its destinations as SOCKS5 hostnames. Do not apply resolver MAP
    // rules: those can block resolution of the numeric proxy address itself.
    const std::string flags = " --proxy-server=socks5://" + host + ":" + service;
    commandW = original;
    commandA = Real_GetCommandLineA();
    commandW.append(flags.begin(), flags.end());
    commandA += flags;
    // DWrite is an import of Discord.exe, so these hooks run before its CRT
    // and Chromium initialize their command-line arguments.
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&Real_GetCommandLineW), ProxyCommandLineW);
    DetourAttach(reinterpret_cast<PVOID*>(&Real_GetCommandLineA), ProxyCommandLineA);
    attached = DetourTransactionCommit() == NO_ERROR;
}

void DetachBrowserProxy() {
    if (!attached) return;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(reinterpret_cast<PVOID*>(&Real_GetCommandLineW), ProxyCommandLineW);
    DetourDetach(reinterpret_cast<PVOID*>(&Real_GetCommandLineA), ProxyCommandLineA);
    DetourTransactionCommit();
}
