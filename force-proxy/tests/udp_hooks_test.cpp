// Exercises force-proxy's UDP hooks through a real SOCKS5 proxy by sending
// DNS queries to 1.1.1.1:53 in every send/receive mode the hooks handle.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#pragma comment(lib, "ws2_32.lib")

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { std::printf("  FAIL: " __VA_ARGS__); std::printf("\n"); ++failures; } } while (0)

static std::vector<char> Query(unsigned short id) {
    std::vector<char> q = { (char)(id >> 8), (char)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    for (const char* label : { "example", "com" }) {
        q.push_back((char)strlen(label));
        q.insert(q.end(), label, label + strlen(label));
    }
    const char tail[] = { 0, 0, 1, 0, 1 };
    q.insert(q.end(), tail, tail + 5);
    return q;
}

static sockaddr_in Target() {
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(53);
    char ip[64] = "1.1.1.1";
    GetEnvironmentVariableA("UDP_TEST_TARGET", ip, sizeof(ip));
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static SOCKET BoundSocket(DWORD) {
    // SO_RCVTIMEO only works on sockets created with WSA_FLAG_OVERLAPPED.
    SOCKET s = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    sockaddr_in local = {};
    local.sin_family = AF_INET;
    const auto start = GetTickCount64();
    const int rc = bind(s, (sockaddr*)&local, sizeof(local)); // Triggers SOCKS5 UDP ASSOCIATE.
    std::printf("  bind rc=%d err=%d in %llu ms\n", rc, rc ? WSAGetLastError() : 0, GetTickCount64() - start);
    DWORD timeout = 2000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    // Clash drops/delays the first datagram of a new UDP association, so warm
    // the association up (retrying like a real DNS client), then drain any
    // late duplicate replies before the measured exchange.
    const auto target = Target();
    const auto q = Query(0xABCD);
    char buf[1500];
    bool warm = false;
    for (int i = 0; i < 10 && !warm; ++i) {
        sendto(s, q.data(), (int)q.size(), 0, (const sockaddr*)&target, sizeof(target));
        warm = recvfrom(s, buf, sizeof(buf), 0, nullptr, nullptr) > 0;
    }
    std::printf("  warm-up %s\n", warm ? "ok" : "FAILED (proxy never answered)");
    Sleep(1500);
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    while (recvfrom(s, buf, sizeof(buf), 0, nullptr, nullptr) > 0) {}
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    return s;
}

static void CheckReply(const char* name, const char* buf, DWORD bytes, unsigned short id, const sockaddr_in* from) {
    CHECK(bytes >= 12, "%s: reply too short (%lu bytes)", name, bytes);
    if (bytes < 12) return;
    const unsigned short got = (unsigned short)(((unsigned char)buf[0] << 8) | (unsigned char)buf[1]);
    CHECK(got == id, "%s: DNS id %04x, expected %04x (SOCKS header not stripped?)", name, got, id);
    CHECK((unsigned char)buf[2] & 0x80, "%s: QR bit not set", name);
    if (from) {
        char ip[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &from->sin_addr, ip, sizeof(ip));
        const auto expected = Target();
        CHECK(from->sin_family == AF_INET && from->sin_addr.s_addr == expected.sin_addr.s_addr && ntohs(from->sin_port) == 53,
              "%s: sender %s:%u, expected the DNS server on port 53", name, ip, ntohs(from->sin_port));
    }
    std::printf("  ok: %s (%lu bytes)\n", name, bytes);
}

static void TestSendtoRecvfrom() {
    std::printf("sendto/recvfrom, blocking, with and without from:\n");
    SOCKET s = BoundSocket(0);
    auto target = Target();
    auto q = Query(0x1111);
    int sent = sendto(s, q.data(), (int)q.size(), 0, (sockaddr*)&target, sizeof(target));
    std::printf("  sendto -> %d (err %d)\n", sent, sent < 0 ? WSAGetLastError() : 0);
    CHECK(sent == (int)q.size(), "sendto returned %d, expected %zu", sent, q.size());
    char buf[1500];
    sockaddr_in from = {};
    int fromLen = sizeof(from);
    int got = recvfrom(s, buf, sizeof(buf), 0, (sockaddr*)&from, &fromLen);
    CHECK(got > 0, "recvfrom failed, error %d", WSAGetLastError());
    if (got > 0) CheckReply("recvfrom(from)", buf, got, 0x1111, &from);

    q = Query(0x2222);
    sendto(s, q.data(), (int)q.size(), 0, (sockaddr*)&target, sizeof(target));
    got = recvfrom(s, buf, sizeof(buf), 0, nullptr, nullptr); // Used to crash.
    CHECK(got > 0, "recvfrom(NULL) failed, error %d", WSAGetLastError());
    if (got > 0) CheckReply("recvfrom(NULL from)", buf, got, 0x2222, nullptr);
    closesocket(s);
}

static void TestMultiBufferSync() {
    std::printf("WSASendTo with 2 buffers / WSARecvFrom into 2 buffers, synchronous:\n");
    SOCKET s = BoundSocket(0);
    auto target = Target();
    auto q = Query(0x3333);
    WSABUF out[2] = { { 5, q.data() }, { (ULONG)q.size() - 5, q.data() + 5 } };
    DWORD sent = 0;
    int rc = WSASendTo(s, out, 2, &sent, 0, (sockaddr*)&target, sizeof(target), nullptr, nullptr);
    CHECK(rc == 0 && sent == q.size(), "WSASendTo rc=%d sent=%lu expected %zu", rc, sent, q.size());
    char a[6], b[1500];
    WSABUF in[2] = { { sizeof(a), a }, { sizeof(b), b } };
    DWORD got = 0, flags = 0;
    sockaddr_in from = {};
    int fromLen = sizeof(from);
    rc = WSARecvFrom(s, in, 2, &got, &flags, (sockaddr*)&from, &fromLen, nullptr, nullptr);
    CHECK(rc == 0, "WSARecvFrom failed, error %d", WSAGetLastError());
    if (rc == 0) {
        std::vector<char> joined(a, a + sizeof(a));
        joined.insert(joined.end(), b, b + (got > sizeof(a) ? got - sizeof(a) : 0));
        CheckReply("WSARecvFrom(2 buffers)", joined.data(), got, 0x3333, &from);
    }
    closesocket(s);
}

static void TestOverlappedEvent() {
    std::printf("Overlapped with event + WSAGetOverlappedResult:\n");
    SOCKET s = BoundSocket(WSA_FLAG_OVERLAPPED);
    auto target = Target();
    char buf[1500];
    WSABUF in = { sizeof(buf), buf };
    WSAOVERLAPPED rov = {};
    rov.hEvent = WSACreateEvent();
    DWORD got = 0, flags = 0;
    sockaddr_in from = {};
    int fromLen = sizeof(from);
    // Post the receive first so it is genuinely pending (the case that was broken).
    int rc = WSARecvFrom(s, &in, 1, nullptr, &flags, (sockaddr*)&from, &fromLen, &rov, nullptr);
    CHECK(rc == 0 || WSAGetLastError() == WSA_IO_PENDING, "WSARecvFrom error %d", WSAGetLastError());

    auto q = Query(0x4444);
    std::vector<char> copy = q;
    WSABUF out = { (ULONG)copy.size(), copy.data() };
    WSAOVERLAPPED sov = {};
    sov.hEvent = WSACreateEvent();
    rc = WSASendTo(s, &out, 1, nullptr, 0, (sockaddr*)&target, sizeof(target), &sov, nullptr);
    CHECK(rc == 0 || WSAGetLastError() == WSA_IO_PENDING, "WSASendTo error %d", WSAGetLastError());
    DWORD sent = 0;
    BOOL ok = WSAGetOverlappedResult(s, &sov, &sent, TRUE, &flags);
    CHECK(ok && sent == q.size(), "send result ok=%d sent=%lu expected %zu", ok, sent, q.size());

    if (WSAWaitForMultipleEvents(1, &rov.hEvent, TRUE, 8000, FALSE) != WSA_WAIT_EVENT_0) {
        CHECK(false, "overlapped recv: no reply within 8 s");
        CancelIo((HANDLE)s);
    }
    ok = WSAGetOverlappedResult(s, &rov, &got, TRUE, &flags);
    CHECK(ok, "recv result failed, error %d", WSAGetLastError());
    if (ok) CheckReply("overlapped event recv", buf, got, 0x4444, &from);
    WSACloseEvent(rov.hEvent);
    WSACloseEvent(sov.hEvent);
    closesocket(s);
}

static void TestIocp(bool useEx) {
    std::printf("Overlapped with I/O completion port (%s):\n", useEx ? "GetQueuedCompletionStatusEx" : "GetQueuedCompletionStatus");
    SOCKET s = BoundSocket(WSA_FLAG_OVERLAPPED);
    HANDLE port = CreateIoCompletionPort((HANDLE)s, nullptr, 7, 0);
    auto target = Target();
    char buf[1500];
    WSABUF in = { sizeof(buf), buf };
    WSAOVERLAPPED rov = {}, sov = {};
    DWORD flags = 0;
    sockaddr_in from = {};
    int fromLen = sizeof(from);
    int rc = WSARecvFrom(s, &in, 1, nullptr, &flags, (sockaddr*)&from, &fromLen, &rov, nullptr);
    CHECK(rc == 0 || WSAGetLastError() == WSA_IO_PENDING, "WSARecvFrom error %d", WSAGetLastError());
    const unsigned short id = useEx ? 0x6666 : 0x5555;
    auto q = Query(id);
    WSABUF out = { (ULONG)q.size(), q.data() };
    rc = WSASendTo(s, &out, 1, nullptr, 0, (sockaddr*)&target, sizeof(target), &sov, nullptr);
    CHECK(rc == 0 || WSAGetLastError() == WSA_IO_PENDING, "WSASendTo error %d", WSAGetLastError());

    bool sawSend = false, sawRecv = false;
    for (int i = 0; i < 2; ++i) {
        DWORD bytes = 0;
        LPOVERLAPPED ov = nullptr;
        BOOL ok;
        if (useEx) {
            OVERLAPPED_ENTRY entry = {};
            ULONG removed = 0;
            ok = GetQueuedCompletionStatusEx(port, &entry, 1, &removed, 8000, FALSE) && removed == 1;
            bytes = entry.dwNumberOfBytesTransferred;
            ov = entry.lpOverlapped;
        } else {
            ULONG_PTR key = 0;
            ok = GetQueuedCompletionStatus(port, &bytes, &key, &ov, 8000);
        }
        CHECK(ok, "completion %d failed, error %lu", i, GetLastError());
        if (!ok) break;
        if (ov == &sov) {
            sawSend = true;
            CHECK(bytes == q.size(), "IOCP send bytes %lu, expected %zu", bytes, q.size());
        } else if (ov == &rov) {
            sawRecv = true;
            CheckReply("IOCP recv", buf, bytes, id, &from);
        }
    }
    CHECK(sawSend && sawRecv, "missing completions send=%d recv=%d", sawSend, sawRecv);
    CloseHandle(port);
    closesocket(s);
}

static DWORD routineBytes = 0;
static bool routineCalled = false;
static void CALLBACK RecvDone(DWORD error, DWORD bytes, LPWSAOVERLAPPED, DWORD) {
    routineCalled = error == 0;
    routineBytes = bytes;
}

static void TestCompletionRoutine() {
    std::printf("Overlapped with completion routine:\n");
    SOCKET s = BoundSocket(WSA_FLAG_OVERLAPPED);
    auto target = Target();
    char buf[1500];
    WSABUF in = { sizeof(buf), buf };
    WSAOVERLAPPED rov = {};
    DWORD flags = 0;
    sockaddr_in from = {};
    int fromLen = sizeof(from);
    int rc = WSARecvFrom(s, &in, 1, nullptr, &flags, (sockaddr*)&from, &fromLen, &rov, RecvDone);
    CHECK(rc == 0 || WSAGetLastError() == WSA_IO_PENDING, "WSARecvFrom error %d", WSAGetLastError());
    auto q = Query(0x7777);
    sendto(s, q.data(), (int)q.size(), 0, (sockaddr*)&target, sizeof(target));
    for (int i = 0; i < 80 && !routineCalled; ++i) SleepEx(100, TRUE);
    CHECK(routineCalled, "completion routine not called");
    if (routineCalled) CheckReply("completion routine recv", buf, routineBytes, 0x7777, &from);
    closesocket(s);
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
    if (argc > 1 && strcmp(argv[1], "nodll") == 0) {
        std::printf("(running WITHOUT force-proxy.dll)\n");
    } else if (!LoadLibraryW(L"force-proxy.dll")) {
        std::printf("cannot load force-proxy.dll (%lu)\n", GetLastError());
        return 2;
    }
    TestSendtoRecvfrom();
    TestMultiBufferSync();
    TestOverlappedEvent();
    TestIocp(false);
    TestIocp(true);
    TestCompletionRoutine();
    std::printf(failures ? "\n%d FAILURE(S)\n" : "\nALL UDP TESTS PASSED\n", failures);
    return failures ? 1 : 0;
}
