#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa)) return 1;
    SetEnvironmentVariableA("SOCKS5_PROXY_ADDRESS", "127.0.0.1");
    if (!getenv("SOCKS5_PROXY_PORT")) SetEnvironmentVariableA("SOCKS5_PROXY_PORT", "7897");
    SetEnvironmentVariableA("SOCKS5_DNS_LOG", "1");
    if (!LoadLibraryA("force-proxy.dll")) { std::cerr << "Cannot load DLL: " << GetLastError() << '\n'; return 1; }
    const char* name = argc > 1 ? argv[1] : "discord.com";
    ADDRINFOA hints = {}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    ADDRINFOA* result = nullptr;
    const int status = getaddrinfo(name,"443",&hints,&result);
    std::cout << "getaddrinfo status=" << status << '\n';
    if (status) return 2;
    for (auto item = result; item; item = item->ai_next) {
        char ip[INET_ADDRSTRLEN] = {};
        InetNtopA(AF_INET, &reinterpret_cast<sockaddr_in*>(item->ai_addr)->sin_addr, ip, sizeof(ip));
        std::cout << name << " -> " << ip << '\n';
    }
    freeaddrinfo(result);
    std::wstring wideName(name,name+strlen(name));
    ADDRINFOW wideHints = {}; wideHints.ai_socktype = SOCK_STREAM;
    ADDRINFOW* wideResult = nullptr;
    const int wideStatus = GetAddrInfoW(wideName.c_str(),L"443",&wideHints,&wideResult);
    std::cout << "GetAddrInfoW status=" << wideStatus << '\n';
    if (wideStatus) return 3;
    FreeAddrInfoW(wideResult);
    const bool legacySuccess = gethostbyname(name) != nullptr;
    std::cout << "gethostbyname success=" << legacySuccess << '\n';
    if (!legacySuccess) return 4;
    sockaddr_in target = {}; target.sin_family = AF_INET; target.sin_port = htons(80);
    InetPtonA(AF_INET, "1.1.1.1", &target.sin_addr);
    SOCKET s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    DWORD timeout = 10000;
    setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
    setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
    if (connect(s,reinterpret_cast<sockaddr*>(&target),sizeof(target)) == SOCKET_ERROR) {
        std::cerr << "Proxied TCP connection failed: " << WSAGetLastError() << '\n'; closesocket(s); return 5;
    }
    const char request[] = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    if (send(s,request,sizeof(request)-1,0) == SOCKET_ERROR) { closesocket(s); return 6; }
    char response[4096] = {};
    const int bytes = recv(s,response,sizeof(response)-1,0);
    closesocket(s);
    if (bytes <= 0) { std::cerr << "Proxied TCP response failed\n"; return 7; }
    std::cout << "Proxied TCP response: " << std::string(response,bytes) << '\n';
    // Process exit unloads the DLL after CRT thread-local data has been cleaned up.
    return 0;
}
