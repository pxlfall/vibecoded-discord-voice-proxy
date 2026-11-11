#pragma once

extern IN_ADDR g_ProxyAddress;
extern uint16_t g_ProxyPort;
extern uint32_t g_ProxyTimeout;
extern char g_ProxyLogin[256];
extern char g_ProxyPassword[256]; 

typedef struct {
	SOCKET proxySocket;
	sockaddr_in udpProxyAddr;
} udp_association_entry_t;

int ConnectThroughSocks5(SOCKET s, const struct sockaddr_in* targetAddr, bool nonBlocking);
bool InitializeSocks5UdpAssociation(udp_association_entry_t* entry);
// Builds one SOCKS5 UDP datagram from all buffers. Caller frees target->buf.
bool EncapsulateUDPBuffers(WSABUF* target, const WSABUF* buffers, DWORD count, const sockaddr* lpTo);
// Strips the SOCKS5 UDP header in place, updates *bytes and the sender address.
// Returns false (and sets *bytes to 0) for malformed or fragmented datagrams.
bool DecapsulateUDPBuffers(const WSABUF* buffers, DWORD count, DWORD* bytes, sockaddr* from, LPINT fromlen);