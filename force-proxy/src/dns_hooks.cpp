#include "stdafx.h"
#include "dns_hooks.h"
#include "dns_wire.h"
#include <curl/curl.h>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>

namespace {
decltype(&getaddrinfo) Real_getaddrinfo = getaddrinfo;
decltype(&GetAddrInfoW) Real_GetAddrInfoW = GetAddrInfoW;
decltype(&freeaddrinfo) Real_freeaddrinfo = freeaddrinfo;
decltype(&FreeAddrInfoW) Real_FreeAddrInfoW = FreeAddrInfoW;
decltype(&gethostbyname) Real_gethostbyname = gethostbyname;
thread_local bool inDoh = false;

// Keep returned A records because the upstream socket proxy only supports IPv4.
struct CacheEntry {
    proxydns::Answer answer;
    std::chrono::steady_clock::time_point expires;
};
std::mutex cacheMutex, allocationMutex, logMutex;
std::map<std::string, CacheEntry> cache;
std::map<void*, bool> allocations;
bool separateWideFree = true;

bool Enabled() {
    char setting[8] = {};
    GetEnvironmentVariableA("SOCKS5_PROXY_DNS", setting, sizeof(setting));
    return std::strcmp(setting, "0") != 0;
}
void Log(const std::string& message) {
    char setting[8] = {};
    GetEnvironmentVariableA("SOCKS5_DNS_LOG", setting, sizeof(setting));
    if (std::strcmp(setting, "1") != 0) return;
    std::lock_guard<std::mutex> lock(logMutex);
    wchar_t dir[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"LOCALAPPDATA", dir, MAX_PATH)) return;
    const std::wstring directory = std::wstring(dir) + L"\\DiscordProxy";
    CreateDirectoryW(directory.c_str(), nullptr);
    FILE* file = nullptr;
    if (_wfopen_s(&file, (directory + L"\\dns.log").c_str(), L"a") != 0) return;
    SYSTEMTIME now;
    GetLocalTime(&now);
    std::fprintf(file, "%04u-%02u-%02u %02u:%02u:%02u pid=%lu %s\n", now.wYear, now.wMonth,
        now.wDay, now.wHour, now.wMinute, now.wSecond, GetCurrentProcessId(), message.c_str());
    std::fclose(file);
}
bool NumericOrLocal(const char* name) {
    if (!name || !*name || _stricmp(name, "localhost") == 0 || _stricmp(name, "localhost.") == 0 ||
        _stricmp(name, "..localmachine") == 0) return true;
    IN_ADDR v4;
    IN6_ADDR v6;
    return InetPtonA(AF_INET, name, &v4) == 1 || InetPtonA(AF_INET6, name, &v6) == 1;
}
std::string AsciiName(const wchar_t* name) {
    if (!name) return {};
    wchar_t ascii[256] = {};
    if (!IdnToAscii(0, name, -1, ascii, 256)) return {};
    std::string result;
    for (const auto c : ascii) {
        if (!c) break;
        if (c > 127) return {};
        result += static_cast<char>(c);
    }
    return result;
}
size_t ReceiveBody(char* data, size_t size, size_t count, void* context) {
    auto& body = *static_cast<std::vector<uint8_t>*>(context);
    if (size && count > 65535 / size) return 0;
    const size_t length = size * count;
    if (length > 65535 - body.size()) return 0;
    try { body.insert(body.end(), data, data + length); }
    catch (...) { return 0; }
    return length;
}
proxydns::Answer Query(const std::string& name) {
    auto packet = proxydns::MakeQuery(name);
    if (packet.empty()) return {};
    static const CURLcode initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (initialized != CURLE_OK) return {};
    struct Guard {
        Guard() { inDoh = true; }
        ~Guard() { inDoh = false; }
    } guard;
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) return {};
    char proxyAddress[INET_ADDRSTRLEN] = {};
    InetNtopA(AF_INET, &g_ProxyAddress, proxyAddress, sizeof(proxyAddress));
    const auto proxy = std::string("socks5h://") + proxyAddress + ":" + std::to_string(ntohs(g_ProxyPort));
    // The IP URL avoids needing DNS to bootstrap DNS. TLS verifies the IP SAN.
    curl_easy_setopt(curl.get(), CURLOPT_URL, "https://1.1.1.1/dns-query");
    curl_easy_setopt(curl.get(), CURLOPT_PROXY, proxy.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_NOPROXY, ""); // Ignore NO_PROXY overrides.
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    // Keep certificate validation, but tolerate unreachable Windows CRL servers.
    // A known revoked certificate still fails; this is not --insecure.
    curl_easy_setopt(curl.get(), CURLOPT_SSL_OPTIONS, CURLSSLOPT_REVOKE_BEST_EFFORT);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(curl.get(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (g_ProxyLogin[0]) {
        curl_easy_setopt(curl.get(), CURLOPT_PROXYUSERNAME, g_ProxyLogin);
        curl_easy_setopt(curl.get(), CURLOPT_PROXYPASSWORD, g_ProxyPassword);
    }
    curl_slist* rawHeaders = nullptr;
    for (const char* header : {"Content-Type: application/dns-message", "Accept: application/dns-message"}) {
        auto next = curl_slist_append(rawHeaders, header);
        if (!next) { curl_slist_free_all(rawHeaders); return {}; }
        rawHeaders = next;
    }
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(rawHeaders, curl_slist_free_all);
    std::vector<uint8_t> body;
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, packet.data());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(packet.size()));
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, ReceiveBody);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &body);
    const auto status = curl_easy_perform(curl.get());
    long httpStatus = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &httpStatus);
    if (status != CURLE_OK || httpStatus != 200) {
        Log("DoH FAILED " + name + " curl=" + std::to_string(status) + " http=" + std::to_string(httpStatus));
        proxydns::Answer failure;
        failure.status = proxydns::Status::server_error;
        return failure;
    }
    auto answer = proxydns::ParseAnswer(body, name);
    std::string details = "DoH " + name;
    for (const auto& address : answer.addresses) {
        details += " " + std::to_string(address[0]) + "." + std::to_string(address[1]) + "." +
            std::to_string(address[2]) + "." + std::to_string(address[3]);
    }
    Log(details + " status=" + std::to_string(static_cast<int>(answer.status)));
    return answer;
}
proxydns::Answer Resolve(std::string name) {
    for (auto& c : name) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    if (!name.empty() && name.back() == '.') name.pop_back();
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        const auto it = cache.find(name);
        if (it != cache.end() && it->second.expires > std::chrono::steady_clock::now()) return it->second.answer;
    }
    auto answer = Query(name);
    if (answer.status == proxydns::Status::ok && answer.ttl) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        if (cache.size() >= 256) cache.erase(cache.begin());
        cache[name] = {answer, std::chrono::steady_clock::now() + std::chrono::seconds(answer.ttl)};
    }
    return answer;
}
int Error(const proxydns::Answer& answer) {
    return answer.status == proxydns::Status::not_found ? WSAHOST_NOT_FOUND : WSATRY_AGAIN;
}
template<class Info> void FreeResult(Info* result) {
    while (result) {
        auto next = result->ai_next;
        std::free(result->ai_addr);
        std::free(result->ai_canonname);
        std::free(result);
        result = next;
    }
}
template<class Info> int MakeResult(const proxydns::Answer& answer, const char* service,
                                  const Info* hints, Info** output) {
    if (!output) return WSAEFAULT;
    *output = nullptr;
    if (hints && hints->ai_family == AF_INET6) return WSANO_DATA;
    if (hints && hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET) return WSAEAFNOSUPPORT;
    // Let Winsock validate socket/protocol/service combinations without looking up a name.
    ADDRINFOA numericHints = {};
    if (hints) {
        numericHints.ai_socktype = hints->ai_socktype;
        numericHints.ai_protocol = hints->ai_protocol;
        numericHints.ai_flags = hints->ai_flags & AI_NUMERICSERV;
    }
    numericHints.ai_family = AF_INET;
    numericHints.ai_flags |= AI_NUMERICHOST;
    ADDRINFOA* native = nullptr;
    const int status = Real_getaddrinfo("127.0.0.1", service, &numericHints, &native);
    if (status) return status;
    std::unique_ptr<ADDRINFOA, decltype(Real_freeaddrinfo)> owner(native, Real_freeaddrinfo);
    Info* first = nullptr;
    Info** tail = &first;
    try {
        for (const auto& ip : answer.addresses) {
            for (auto model = native; model; model = model->ai_next) {
                auto item = static_cast<Info*>(std::calloc(1, sizeof(Info)));
                if (!item) throw std::bad_alloc();
                *tail = item;
                tail = &item->ai_next;
                item->ai_flags = hints ? hints->ai_flags : 0;
                item->ai_family = AF_INET;
                item->ai_socktype = model->ai_socktype;
                item->ai_protocol = model->ai_protocol;
                item->ai_addrlen = sizeof(sockaddr_in);
                auto address = static_cast<sockaddr_in*>(std::calloc(1, sizeof(sockaddr_in)));
                if (!address) throw std::bad_alloc();
                item->ai_addr = reinterpret_cast<sockaddr*>(address);
                *address = *reinterpret_cast<sockaddr_in*>(model->ai_addr);
                std::memcpy(&address->sin_addr, ip.data(), 4);
            }
        }
        if (first && hints && (hints->ai_flags & AI_CANONNAME)) {
            using Char = std::remove_pointer_t<decltype(first->ai_canonname)>;
            first->ai_canonname = static_cast<Char*>(std::calloc(answer.canonical.size() + 1, sizeof(Char)));
            if (!first->ai_canonname) throw std::bad_alloc();
            std::copy(answer.canonical.begin(), answer.canonical.end(), first->ai_canonname);
        }
        if (!first) return WSANO_DATA;
        std::lock_guard<std::mutex> lock(allocationMutex);
        allocations[first] = std::is_same_v<Info, ADDRINFOW>;
        *output = first;
        return 0;
    } catch (...) {
        FreeResult(first);
        return WSA_NOT_ENOUGH_MEMORY;
    }
}
int WSAAPI Mine_getaddrinfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, ADDRINFOA** result) {
    if (!Enabled() || NumericOrLocal(node) || (hints && (hints->ai_flags & AI_NUMERICHOST)))
        return Real_getaddrinfo(node, service, hints, result);
    if (result) *result = nullptr;
    int status;
    try {
        if (inDoh) status = WSATRY_AGAIN;
        else {
            auto answer = Resolve(node);
            status = answer.status == proxydns::Status::ok ? MakeResult(answer, service, hints, result) : Error(answer);
        }
    } catch (...) { status = WSA_NOT_ENOUGH_MEMORY; }
    WSASetLastError(status);
    return status;
}
int WSAAPI Mine_GetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, ADDRINFOW** result) {
    if (!Enabled() || !node || !*node || (hints && (hints->ai_flags & AI_NUMERICHOST)))
        return Real_GetAddrInfoW(node, service, hints, result);
    if (result) *result = nullptr;
    int status;
    try {
        auto ascii = AsciiName(node);
        if (!ascii.empty() && NumericOrLocal(ascii.c_str())) return Real_GetAddrInfoW(node, service, hints, result);
        if (ascii.empty()) status = WSAHOST_NOT_FOUND;
        else if (inDoh) status = WSATRY_AGAIN;
        else {
            auto answer = Resolve(ascii);
            std::string serviceAscii;
            if (service) for (auto c = service; *c; ++c) {
                if (*c > 127) { WSASetLastError(WSATYPE_NOT_FOUND); return WSATYPE_NOT_FOUND; }
                serviceAscii += static_cast<char>(*c);
            }
            status = answer.status == proxydns::Status::ok ?
                MakeResult(answer, service ? serviceAscii.c_str() : nullptr, hints, result) : Error(answer);
        }
    } catch (...) { status = WSA_NOT_ENOUGH_MEMORY; }
    WSASetLastError(status);
    return status;
}
bool FreeOwned(void* result) {
    bool wide;
    {
        std::lock_guard<std::mutex> lock(allocationMutex);
        auto it = allocations.find(result);
        if (it == allocations.end()) return false;
        wide = it->second;
        allocations.erase(it);
    }
    if (wide) FreeResult(static_cast<ADDRINFOW*>(result));
    else FreeResult(static_cast<ADDRINFOA*>(result));
    return true;
}
void WSAAPI Mine_freeaddrinfo(ADDRINFOA* result) {
    if (!FreeOwned(result)) Real_freeaddrinfo(result);
}
void WSAAPI Mine_FreeAddrInfoW(ADDRINFOW* result) {
    if (!FreeOwned(result)) Real_FreeAddrInfoW(result);
}
hostent* WSAAPI Mine_gethostbyname(const char* name) {
    if (!Enabled() || NumericOrLocal(name)) return Real_gethostbyname(name);
    try {
        if (inDoh) { WSASetLastError(WSATRY_AGAIN); return nullptr; }
        auto answer = Resolve(name);
        if (answer.status != proxydns::Status::ok) { WSASetLastError(Error(answer)); return nullptr; }
        struct LegacyResult {
            hostent entry = {};
            std::string name;
            std::vector<std::array<uint8_t, 4>> ips;
            std::vector<char*> addresses;
            char* aliases[1] = {nullptr};
        };
        thread_local LegacyResult result;
        result.name = answer.canonical;
        result.ips = std::move(answer.addresses);
        result.addresses.clear();
        for (auto& ip : result.ips) result.addresses.push_back(reinterpret_cast<char*>(ip.data()));
        result.addresses.push_back(nullptr);
        result.entry.h_name = result.name.data();
        result.entry.h_aliases = result.aliases;
        result.entry.h_addrtype = AF_INET;
        result.entry.h_length = 4;
        result.entry.h_addr_list = result.addresses.data();
        WSASetLastError(0);
        return &result.entry;
    } catch (...) { WSASetLastError(WSA_NOT_ENOUGH_MEMORY); return nullptr; }
}
}
void AttachDnsHooks() {
    // Some Windows versions export both free functions at the same address.
    separateWideFree = reinterpret_cast<PVOID>(Real_freeaddrinfo) != reinterpret_cast<PVOID>(Real_FreeAddrInfoW);
    DetourAttach(reinterpret_cast<PVOID*>(&Real_getaddrinfo), Mine_getaddrinfo);
    DetourAttach(reinterpret_cast<PVOID*>(&Real_GetAddrInfoW), Mine_GetAddrInfoW);
    DetourAttach(reinterpret_cast<PVOID*>(&Real_freeaddrinfo), Mine_freeaddrinfo);
    if (separateWideFree) DetourAttach(reinterpret_cast<PVOID*>(&Real_FreeAddrInfoW), Mine_FreeAddrInfoW);
    DetourAttach(reinterpret_cast<PVOID*>(&Real_gethostbyname), Mine_gethostbyname);
}
void DetachDnsHooks() {
    DetourDetach(reinterpret_cast<PVOID*>(&Real_getaddrinfo), Mine_getaddrinfo);
    DetourDetach(reinterpret_cast<PVOID*>(&Real_GetAddrInfoW), Mine_GetAddrInfoW);
    DetourDetach(reinterpret_cast<PVOID*>(&Real_freeaddrinfo), Mine_freeaddrinfo);
    if (separateWideFree) DetourDetach(reinterpret_cast<PVOID*>(&Real_FreeAddrInfoW), Mine_FreeAddrInfoW);
    DetourDetach(reinterpret_cast<PVOID*>(&Real_gethostbyname), Mine_gethostbyname);
}
