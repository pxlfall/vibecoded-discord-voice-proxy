#include "stdafx.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "detours.lib")

IN_ADDR g_ProxyAddress;
uint16_t g_ProxyPort;
uint32_t g_ProxyTimeout; 
char g_ProxyLogin[256];  
char g_ProxyPassword[256]; 

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        { 

            char addressBuff[MAX_PATH] = "127.0.0.1";
            char portBuff[MAX_PATH] = "12334";
            char timeoutBuff[MAX_PATH]; 

            DisableThreadLibraryCalls(hModule);
            DetourRestoreAfterWith();

            GetEnvironmentVariableA("SOCKS5_PROXY_ADDRESS", addressBuff, sizeof(addressBuff));
            GetEnvironmentVariableA("SOCKS5_PROXY_PORT", portBuff, sizeof(portBuff));

            g_ProxyLogin[0] = '\0';
            g_ProxyPassword[0] = '\0';
            GetEnvironmentVariableA("SOCKS5_PROXY_LOGIN", g_ProxyLogin, sizeof(g_ProxyLogin) - 1);
            GetEnvironmentVariableA("SOCKS5_PROXY_PASSWORD", g_ProxyPassword, sizeof(g_ProxyPassword) - 1);

            inet_pton(AF_INET, addressBuff, &g_ProxyAddress);
            g_ProxyPort = htons(static_cast<uint16_t>(strtol(portBuff, nullptr, 10)));

            DWORD timeoutEnvLen = GetEnvironmentVariableA("SOCKS5_PROXY_TIMEOUT", timeoutBuff, sizeof(timeoutBuff) - 1);
            if (timeoutEnvLen == 0 || timeoutEnvLen >= (sizeof(timeoutBuff) - 1) ) {
                g_ProxyTimeout = 30;
            } else {
                timeoutBuff[timeoutEnvLen] = '\0';
                char* endPtr;
                long val = strtol(timeoutBuff, &endPtr, 10);
                if (endPtr == timeoutBuff || *endPtr != '\0' || val <= 0) {
                    g_ProxyTimeout = 30;
                } else {
                    g_ProxyTimeout = static_cast<uint32_t>(val);
                }
            }

            InitHooks();
        } 
        break;

    case DLL_PROCESS_DETACH:
        DestroyHooks();
        break;
    }
    return TRUE;
}

