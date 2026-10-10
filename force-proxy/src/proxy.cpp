#include "stdafx.h"

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

int ConnectToProxy(SOCKET s, bool nonBlocking)
{
    SOCKADDR_IN proxyAddr;
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr = g_ProxyAddress;
    proxyAddr.sin_port = g_ProxyPort;

    auto ret = Real_connect(s, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr));
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        return ret;
    }

    if (nonBlocking) WaitForWrite(s, g_ProxyTimeout);

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


    if (nonBlocking) WaitForWrite(s, g_ProxyTimeout);
    int bytesToSend = (request[1] == 0x01) ? 3 : sizeof(request);
    if (send(s, (const char*)request, bytesToSend, 0) == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }

    //Receive response
    uint8_t response[2];
    if (nonBlocking) WaitForRead(s, g_ProxyTimeout);
    if (recv(s, (char*)response, sizeof(response), 0) <= 0) { 
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

        if (nonBlocking) WaitForWrite(s, g_ProxyTimeout);
        if (send(s, (const char*)authRequest, static_cast<int>(authLen), 0) == SOCKET_ERROR) {
            return SOCKET_ERROR;
        }

        uint8_t authResponse[2];
        if (nonBlocking) WaitForRead(s, g_ProxyTimeout);
        if (recv(s, (char*)authResponse, sizeof(authResponse), 0) <= 0) {
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

    if (nonBlocking) WaitForWrite(s, g_ProxyTimeout);
    send(s, (const char*)connectRequest, sizeof(connectRequest), 0);
    uint8_t connectResponse[10];
    if (nonBlocking) WaitForRead(s, g_ProxyTimeout);
    recv(s, (char*)connectResponse, sizeof(connectResponse), 0);

    if (connectResponse[1] != 0x00) {
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

    SetNonBlockingMode(entry->proxySocket, true);
    /*int iOptval = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        (char*)&iOptval, sizeof(iOptval));*/

    if (ConnectToProxy(entry->proxySocket, true) != ERROR_SUCCESS) {
        return false;
    }

    if (SendSocks5Handshake(entry->proxySocket, true) != ERROR_SUCCESS) {
        return false;
    }

    // Request UDP associate
    // We don't have to specify dst since proxies usually get it from encapsulating header
    uint8_t udpAssociateRequest[10] = { 0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }; // SOCKS5, UDP ASSOCIATE, reserved, IPv4, dst addr, dst port
    WaitForWrite(entry->proxySocket, g_ProxyTimeout);
    send(entry->proxySocket, (const char*)udpAssociateRequest, sizeof(udpAssociateRequest), 0);

    uint8_t udpAssociateResponse[10];
    WaitForRead(entry->proxySocket, g_ProxyTimeout);
    recv(entry->proxySocket, (char*)udpAssociateResponse, sizeof(udpAssociateResponse), 0);

    if (udpAssociateResponse[1] != 0x00) {
        return false;
    }

    //Real_closesocket(s);

    // Get address and port to send UDP packets
    entry->udpProxyAddr.sin_family = AF_INET;
    memcpy(&entry->udpProxyAddr.sin_addr, udpAssociateResponse + 4, 4);
    memcpy(&entry->udpProxyAddr.sin_port, udpAssociateResponse + 8, 2);

    return true;
}

void EncapsulateUDPPacket(WSABUF* target, char *buf, int len, const sockaddr* lpTo)
{
    target->len = len + 10; // packet len + encasulated size
    target->buf = (char *)malloc(target->len);

    target->buf[0] = 0; // Reserved
    target->buf[1] = 0; // Reserved
    target->buf[2] = 0; // Fragmentation flag
    target->buf[3] = 1; // IPv4

    const struct sockaddr_in* addr = reinterpret_cast<const struct sockaddr_in*>(lpTo);
    memcpy(&target->buf[4], &addr->sin_addr.s_addr, sizeof(addr->sin_addr.s_addr)); //ip addr
    memcpy(&target->buf[8], &addr->sin_port, sizeof(addr->sin_port)); // port

    memcpy(&target->buf[10], buf, len); //copy whole packet
}

void ExtractSockAddr(char* buf, sockaddr* target)
{
    const struct sockaddr_in* addr = reinterpret_cast<const struct sockaddr_in*>(target);
    memcpy((void*)&addr->sin_addr.s_addr, &buf[4], sizeof(addr->sin_addr.s_addr)); //ip addr
    memcpy((void*)&addr->sin_port, &buf[8], sizeof(addr->sin_port)); // port
}