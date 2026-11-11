#include "stdafx.h"
#include <algorithm>

// Глобальные переменные g_ProxyAddress, g_ProxyPort, g_ProxyTimeout, g_ProxyLogin, g_ProxyPassword теперь в dllmain.cpp


bool WaitForWrite(SOCKET s, int timeoutSec)
{
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(s, &writeSet);

    timeval timeout = { timeoutSec, 0 };
    int result = select(0, NULL, &writeSet, NULL, &timeout);
    if (result > 0 && FD_ISSET(s, &writeSet)) {
        return true;
    }

    return false;
}

bool WaitForRead(SOCKET s, int timeoutSec)
{
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(s, &readSet);

    timeval timeout = { timeoutSec, 0 };
    int result = select(0, &readSet, NULL, NULL, &timeout);
    if (result > 0 && FD_ISSET(s, &readSet)) {
        return true;
    }

    return false;
}

bool SetNonBlockingMode(SOCKET s, bool nonBlocked)
{
    u_long mode = nonBlocked;
    return Real_ioctlsocket(s, FIONBIO, &mode) == NO_ERROR;
}

// Send exactly len bytes. On non-blocking sockets wait (up to the proxy
// timeout) whenever the socket would block instead of ignoring the result.
bool SendAll(SOCKET s, const void* data, int len, bool nonBlocking)
{
    auto bytes = static_cast<const char*>(data);
    while (len > 0) {
        if (nonBlocking && !WaitForWrite(s, g_ProxyTimeout)) return false;
        const int sent = send(s, bytes, len, 0);
        if (sent == SOCKET_ERROR) {
            if (nonBlocking && WSAGetLastError() == WSAEWOULDBLOCK) continue;
            return false;
        }
        bytes += sent;
        len -= sent;
    }
    return true;
}

// Receive exactly len bytes; a closed connection or timeout is a failure.
bool RecvExact(SOCKET s, void* data, int len, bool nonBlocking)
{
    auto bytes = static_cast<char*>(data);
    while (len > 0) {
        if (nonBlocking && !WaitForRead(s, g_ProxyTimeout)) return false;
        const int received = recv(s, bytes, len, 0);
        if (received == 0) return false;
        if (received == SOCKET_ERROR) {
            if (nonBlocking && WSAGetLastError() == WSAEWOULDBLOCK) continue;
            return false;
        }
        bytes += received;
        len -= received;
    }
    return true;
}

// Read a SOCKS5 CONNECT / UDP ASSOCIATE reply. Returns the bound IPv4
// address/port when the reply carries one; other address types are consumed.
bool ReadSocks5Reply(SOCKET s, bool nonBlocking, sockaddr_in* bound)
{
    uint8_t header[4];
    if (!RecvExact(s, header, sizeof(header), nonBlocking)) return false;
    if (header[0] != 0x05 || header[1] != 0x00) return false;

    uint8_t rest[255 + 2];
    int restLen;
    switch (header[3]) {
    case 0x01: restLen = 4 + 2; break;
    case 0x04: restLen = 16 + 2; break;
    case 0x03: {
        uint8_t nameLen;
        if (!RecvExact(s, &nameLen, 1, nonBlocking)) return false;
        restLen = nameLen + 2;
        break;
    }
    default: return false;
    }
    if (!RecvExact(s, rest, restLen, nonBlocking)) return false;

    if (bound) {
        if (header[3] != 0x01) return false; // We can only relay UDP to an IPv4 address.
        bound->sin_family = AF_INET;
        memcpy(&bound->sin_addr, rest, 4);
        memcpy(&bound->sin_port, rest + 4, 2);
    }
    return true;
}

int ConnectToProxy(SOCKET s, bool nonBlocking)
{
    SOCKADDR_IN proxyAddr = {};
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr = g_ProxyAddress;
    proxyAddr.sin_port = g_ProxyPort;

    auto ret = Real_connect(s, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr));
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        return ret;
    }

    if (nonBlocking) {
        // A failed non-blocking connect never becomes writable, so a timeout
        // here is a failure. Check SO_ERROR for connects that did complete.
        if (!WaitForWrite(s, g_ProxyTimeout)) {
            WSASetLastError(WSAETIMEDOUT);
            return SOCKET_ERROR;
        }
        int error = 0;
        int errorLen = sizeof(error);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&error, &errorLen) != 0 || error != 0) {
            WSASetLastError(error ? error : WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
    }

    return ERROR_SUCCESS;
}

int SendSocks5Handshake(SOCKET s, bool nonBlocking)
{
    //Send socks5 handshake
    uint8_t request[] = { 0x05, 0x02, 0x00, 0x02 }; 
    if (strlen(g_ProxyLogin) == 0 && strlen(g_ProxyPassword) == 0) { 
        request[1] = 0x01; 
        request[2] = 0x00; 

    }


    int bytesToSend = (request[1] == 0x01) ? 3 : sizeof(request);
    if (!SendAll(s, request, bytesToSend, nonBlocking)) {
        return SOCKET_ERROR;
    }

    //Receive response
    uint8_t response[2];
    if (!RecvExact(s, response, sizeof(response), nonBlocking)) {
        return SOCKET_ERROR;
    }

    if (response[0] != 0x05) {
        return SOCKET_ERROR;
    }

    if (response[1] == 0x02) { //login/password auth
        if (strlen(g_ProxyLogin) == 0 && strlen(g_ProxyPassword) == 0) {
            return SOCKET_ERROR;
        }
        size_t loginLen = strlen(g_ProxyLogin);
        size_t passwordLen = strlen(g_ProxyPassword);

        if (loginLen > 255 || passwordLen > 255) {
            return SOCKET_ERROR; 
        }

        size_t authLen = 0;
        uint8_t authRequest[1 + 1 + 255 + 1 + 255];  
        authRequest[authLen++] = 0x01; // Authentication subprotocol version

        authRequest[authLen++] = (uint8_t)loginLen;
        memcpy(&authRequest[authLen], g_ProxyLogin, loginLen);
        authLen += loginLen;

        authRequest[authLen++] = (uint8_t)passwordLen;
        memcpy(&authRequest[authLen], g_ProxyPassword, passwordLen);
        authLen += passwordLen;

        if (!SendAll(s, authRequest, static_cast<int>(authLen), nonBlocking)) {
            return SOCKET_ERROR;
        }

        uint8_t authResponse[2];
        if (!RecvExact(s, authResponse, sizeof(authResponse), nonBlocking)) {
            return SOCKET_ERROR;
        }

        if (authResponse[0] != 0x01 || authResponse[1] != 0x00) {
            return SOCKET_ERROR;  // Authentication failed
        }
    } else if (response[1] == 0x00) { // No authentication required
    }
    else if (response[1] == 0xFF) { // No acceptable methods
        return SOCKET_ERROR; 
    }
     else {
        return SOCKET_ERROR;  // Server requires an unsupported authentication method or другая ошибка
    }

    return ERROR_SUCCESS;
}


int ConnectThroughSocks5(SOCKET s, const struct sockaddr_in* targetAddr, bool nonBlocking)
{
    if (ConnectToProxy(s, nonBlocking) != ERROR_SUCCESS) {
        return SOCKET_ERROR;
    }

    if (SendSocks5Handshake(s, nonBlocking) != ERROR_SUCCESS) {
        return SOCKET_ERROR;
    }

    // send CONNECT request
    uint8_t connectRequest[10] = { 0x05, 0x01, 0x00, 0x01 }; // SOCKS5, CONNECT, reserved, IPv4
    memcpy(connectRequest + 4, &targetAddr->sin_addr, 4); // Target ip
    memcpy(connectRequest + 8, &targetAddr->sin_port, 2); // Target port

    if (!SendAll(s, connectRequest, sizeof(connectRequest), nonBlocking) ||
        !ReadSocks5Reply(s, nonBlocking, nullptr)) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;  // Connection error
    }

    if (nonBlocking) {
        WSASetLastError(WSAEWOULDBLOCK);
        return SOCKET_ERROR;
    }

    return ERROR_SUCCESS;    
}

bool InitializeSocks5UdpAssociation(udp_association_entry_t* entry) {
    //We need tmp socket to request udp association
    entry->proxySocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (entry->proxySocket == INVALID_SOCKET) {
        return false;
    }

    // Any failure below must close the control socket; otherwise every failed
    // UDP bind leaks a TCP connection.
    auto fail = [entry]() {
        Real_closesocket(entry->proxySocket);
        entry->proxySocket = INVALID_SOCKET;
        return false;
    };

    if (!SetNonBlockingMode(entry->proxySocket, true)) {
        return fail();
    }

    if (ConnectToProxy(entry->proxySocket, true) != ERROR_SUCCESS) {
        return fail();
    }

    if (SendSocks5Handshake(entry->proxySocket, true) != ERROR_SUCCESS) {
        return fail();
    }

    // Request UDP associate
    // We don't have to specify dst since proxies usually get it from encapsulating header
    uint8_t udpAssociateRequest[10] = { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }; // SOCKS5, UDP ASSOCIATE, reserved, IPv4, dst addr, dst port
    sockaddr_in relay = {};
    if (!SendAll(entry->proxySocket, udpAssociateRequest, sizeof(udpAssociateRequest), true) ||
        !ReadSocks5Reply(entry->proxySocket, true, &relay)) {
        return fail();
    }

    // Proxies listening on all interfaces commonly answer with 0.0.0.0, which
    // means "the address you used to reach me" (RFC 1928 practice).
    if (relay.sin_addr.s_addr == INADDR_ANY) {
        relay.sin_addr = g_ProxyAddress;
    }
    if (relay.sin_port == 0) {
        return fail();
    }

    // Get address and port to send UDP packets
    entry->udpProxyAddr = relay;

    return true;
}

bool EncapsulateUDPBuffers(WSABUF* target, const WSABUF* buffers, DWORD count, const sockaddr* lpTo)
{
    size_t total = 0;
    for (DWORD i = 0; i < count; ++i) total += buffers[i].len;
    if (total > 0xFFFF) return false;

    target->len = static_cast<ULONG>(total + 10);
    target->buf = (char*)malloc(target->len);
    if (!target->buf) return false;

    target->buf[0] = 0; // Reserved
    target->buf[1] = 0; // Reserved
    target->buf[2] = 0; // Fragmentation flag
    target->buf[3] = 1; // IPv4

    const struct sockaddr_in* addr = reinterpret_cast<const struct sockaddr_in*>(lpTo);
    memcpy(&target->buf[4], &addr->sin_addr.s_addr, sizeof(addr->sin_addr.s_addr)); //ip addr
    memcpy(&target->buf[8], &addr->sin_port, sizeof(addr->sin_port)); // port

    size_t offset = 10;
    for (DWORD i = 0; i < count; ++i) {
        memcpy(&target->buf[offset], buffers[i].buf, buffers[i].len);
        offset += buffers[i].len;
    }
    return true;
}

bool DecapsulateUDPBuffers(const WSABUF* buffers, DWORD count, DWORD* bytes, sockaddr* from, LPINT fromlen)
{
    // Gather the received datagram (it may span several WSABUFs).
    std::vector<char> packet;
    packet.reserve(*bytes);
    DWORD remaining = *bytes;
    for (DWORD i = 0; i < count && remaining; ++i) {
        const DWORD take = (std::min)(remaining, static_cast<DWORD>(buffers[i].len));
        packet.insert(packet.end(), buffers[i].buf, buffers[i].buf + take);
        remaining -= take;
    }

    // RSV(2) FRAG(1) ATYP(1)=IPv4 ADDR(4) PORT(2). Fragments are unsupported.
    if (packet.size() < 10 || packet[2] != 0 || packet[3] != 1) {
        *bytes = 0;
        return false;
    }

    if (from && (!fromlen || *fromlen >= (int)sizeof(sockaddr_in))) {
        auto addr = reinterpret_cast<sockaddr_in*>(from);
        memset(addr, 0, sizeof(*addr));
        addr->sin_family = AF_INET;
        memcpy(&addr->sin_addr.s_addr, &packet[4], 4);
        memcpy(&addr->sin_port, &packet[8], 2);
        if (fromlen) *fromlen = sizeof(sockaddr_in);
    }

    // Scatter the payload back without the 10-byte header.
    size_t offset = 10;
    for (DWORD i = 0; i < count && offset < packet.size(); ++i) {
        const size_t take = (std::min)(packet.size() - offset, static_cast<size_t>(buffers[i].len));
        memcpy(buffers[i].buf, &packet[offset], take);
        offset += take;
    }
    *bytes = static_cast<DWORD>(packet.size() - 10);
    return true;
}
