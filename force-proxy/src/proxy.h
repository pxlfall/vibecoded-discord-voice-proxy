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
void EncapsulateUDPPacket(WSABUF* target, char* buf, int len, const sockaddr* lpTo);
void ExtractSockAddr(char* buf, sockaddr* target);