#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <Psapi.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;
struct Snapshot { SIZE_T privateBytes; DWORD handles; double cpu; };
Snapshot TakeSnapshot() {
    PROCESS_MEMORY_COUNTERS_EX memory = {};
    GetProcessMemoryInfo(GetCurrentProcess(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),sizeof(memory));
    DWORD handles = 0; GetProcessHandleCount(GetCurrentProcess(),&handles);
    FILETIME created,exited,kernel,user;
    GetProcessTimes(GetCurrentProcess(),&created,&exited,&kernel,&user);
    ULARGE_INTEGER k,u; k.LowPart=kernel.dwLowDateTime;k.HighPart=kernel.dwHighDateTime;
    u.LowPart=user.dwLowDateTime;u.HighPart=user.dwHighDateTime;
    return {memory.PrivateUsage,handles,(k.QuadPart+u.QuadPart)/10000000.0};
}
bool Resolve() {
    ADDRINFOA hints = {}; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    ADDRINFOA* result=nullptr;
    const int status=getaddrinfo("discord.com","443",&hints,&result);
    if (result) freeaddrinfo(result);
    return status==0;
}
int main() {
    WSADATA wsa; if (WSAStartup(MAKEWORD(2,2),&wsa)) return 1;
    SetEnvironmentVariableA("SOCKS5_PROXY_ADDRESS","127.0.0.1");
    SetEnvironmentVariableA("SOCKS5_PROXY_PORT","7897");
    SetEnvironmentVariableA("SOCKS5_DNS_LOG","1");
    if (!LoadLibraryA("force-proxy.dll")) return 2;
    auto start=Clock::now();
    if (!Resolve()) return 3;
    std::cout << "ColdLookupMs=" << std::chrono::duration<double,std::milli>(Clock::now()-start).count() << '\n';
    for (int i=0;i<1000;++i) if (!Resolve()) return 4;
    auto before=TakeSnapshot(); start=Clock::now();
    for (int batch=0;batch<5;++batch) {
        for (int i=0;i<20000;++i) if (!Resolve()) return 5;
        auto now=TakeSnapshot();
        std::cout << "Completed=" << (batch+1)*20000 << " PrivateBytes=" << now.privateBytes << " Handles=" << now.handles << '\n';
    }
    auto after=TakeSnapshot();
    std::cout << "Sequential100kMs=" << std::chrono::duration<double,std::milli>(Clock::now()-start).count()
        << " CpuSeconds=" << after.cpu-before.cpu << " PrivateDeltaBytes=" << static_cast<long long>(after.privateBytes)-static_cast<long long>(before.privateBytes)
        << " HandleDelta=" << static_cast<long long>(after.handles)-before.handles << '\n';
    std::atomic<int> failures=0;
    for (int round=0;round<5;++round) {
        std::vector<std::thread> workers;
        start=Clock::now(); before=TakeSnapshot();
        for (int t=0;t<8;++t) workers.emplace_back([&] { for(int i=0;i<12500;++i) if(!Resolve()) ++failures; });
        for (auto& t:workers) t.join();
        after=TakeSnapshot();
        std::cout << "ParallelRound=" << round+1 << " LookupMs=" << std::chrono::duration<double,std::milli>(Clock::now()-start).count()
            << " CpuSeconds=" << after.cpu-before.cpu << " PrivateBytes=" << after.privateBytes
            << " PrivateDeltaBytes=" << static_cast<long long>(after.privateBytes)-static_cast<long long>(before.privateBytes)
            << " HandleDelta=" << static_cast<long long>(after.handles)-before.handles << " Failures=" << failures.load() << '\n';
    }
    // A cached answer must expire within five minutes; verify a real refresh.
    if (getenv("DNS_PERF_WAIT_TTL")) {
        std::this_thread::sleep_for(std::chrono::seconds(310));
        start=Clock::now(); if(!Resolve()) return 6;
        std::cout << "AfterExpiryMs=" << std::chrono::duration<double,std::milli>(Clock::now()-start).count() << '\n';
    }
    return failures ? 7 : 0;
}
