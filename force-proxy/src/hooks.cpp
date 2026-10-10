#include "stdafx.h"
#include "dns_hooks.h"

#pragma region Detours definations

extern "C" {
	int (WINAPI* Real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;

	int (WINAPI* Real_bind)(SOCKET s, const sockaddr* addr, int namelen) = bind;

	int (WINAPI* Real_closesocket)(SOCKET s) = closesocket;

	int (WINAPI* Real_sendto)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) = sendto;

	int (WINAPI* Real_recvfrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) = recvfrom;

	int (WINAPI* Real_WSASendTo)(
		SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesSent,
		DWORD dwFlags,
		const sockaddr* lpTo,
		int iTolen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSASendTo;

	int (WINAPI* Real_WSARecvFrom)(
		SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesRecvd,
		LPDWORD lpFlags,
		sockaddr* lpFrom,
		LPINT lpFromlen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSARecvFrom;

	int (WSAAPI* Real_WSAEventSelect)(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents) = WSAEventSelect;
	int (WSAAPI* Real_ioctlsocket)(SOCKET s, long cmd, u_long* argp) = ioctlsocket;
}

#pragma endregion


std::shared_mutex g_SocketsMapsMutex;
std::map<SOCKET, udp_association_entry_t> g_UDPAssociateMap;
std::map<SOCKET, long> g_NonBlockingSockets;

bool IsUDPSocket(SOCKET s)
{
	int32_t sockOptVal;
	int32_t sockOptLen = sizeof(sockOptVal);

	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sockOptVal, &sockOptLen) != 0)
		return false;

	return sockOptVal == SOCK_DGRAM;
}

bool IsMultiCastAddr(const sockaddr *addr)
{
	uint32_t ip = ntohl(((SOCKADDR_IN*)addr)->sin_addr.s_addr);

	return (ip & 0xF0000000) == 0xE0000000;
}

bool SocketExistsInUdpAssociationMap(SOCKET s)
{
	g_SocketsMapsMutex.lock_shared();
	bool exists = g_UDPAssociateMap.count(s);
	g_SocketsMapsMutex.unlock_shared();

	return exists;
}

bool SocketExistsInNonBlockingMap(SOCKET s)
{
	g_SocketsMapsMutex.lock_shared();
	bool exists = g_NonBlockingSockets.count(s);
	g_SocketsMapsMutex.unlock_shared();

	return exists;
}

int WSAAPI Mine_WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents)
{

	g_SocketsMapsMutex.lock();
	if (hEventObject != NULL && lNetworkEvents != 0) {
		g_NonBlockingSockets.insert(std::pair<SOCKET, long>(s, lNetworkEvents));
	} else {
		g_NonBlockingSockets.erase(s);
	}
	g_SocketsMapsMutex.unlock();

	return Real_WSAEventSelect(s, hEventObject, lNetworkEvents);
}

int WSAAPI Mine_ioctlsocket(SOCKET s, long cmd, u_long* argp)
{
	if (cmd == FIONBIO) {
		g_SocketsMapsMutex.lock();
		if (*argp) {
			g_NonBlockingSockets.insert(std::pair<SOCKET, long>(s, *argp));
		} else {
			g_NonBlockingSockets.erase(s);
		}
		g_SocketsMapsMutex.unlock();
	}

	return Real_ioctlsocket(s, cmd, argp);
}

int WINAPI Mine_connect(SOCKET s, const sockaddr* name, int namelen)
{
	const struct sockaddr_in* addr_in = reinterpret_cast<const struct sockaddr_in*>(name);

	char taget[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(addr_in->sin_addr), taget, INET_ADDRSTRLEN);

	//skip connection to localhost and proxy server
	if (IsUDPSocket(s) || addr_in->sin_addr.s_addr == g_ProxyAddress.s_addr || !strcmp(taget, "0.0.0.0") || !strcmp(taget, "127.0.0.1")) {
		return Real_connect(s, name, namelen);
	}

	if (addr_in->sin_family == AF_INET) {
		return ConnectThroughSocks5(s, addr_in, SocketExistsInNonBlockingMap(s));
	}

	return Real_connect(s, name, namelen);
}

int WINAPI Mine_bind(SOCKET s, const sockaddr* addr, int namelen)
{
	//not UDP or already exists
	if (!IsUDPSocket(s) || SocketExistsInUdpAssociationMap(s))
		return Real_bind(s, addr, namelen);

	udp_association_entry_t entry;
	if (!InitializeSocks5UdpAssociation(&entry)) {
		return Real_bind(s, addr, namelen);
	}

	g_SocketsMapsMutex.lock();
	g_UDPAssociateMap.insert(std::pair<SOCKET, udp_association_entry_t>(s, entry));
	g_SocketsMapsMutex.unlock();

	return Real_bind(s, addr, namelen);
}

int WINAPI Mine_closesocket(SOCKET s)
{
	g_SocketsMapsMutex.lock();
	if (g_UDPAssociateMap.count(s)) {
		Real_closesocket(g_UDPAssociateMap[s].proxySocket);
		g_UDPAssociateMap.erase(s);
	}	
	g_NonBlockingSockets.erase(s);
	g_SocketsMapsMutex.unlock();

	return Real_closesocket(s);
}

int WINAPI Mine_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
	udp_association_entry_t entryCopy; 
	bool associated = false;

	if (!IsMultiCastAddr(to)) { 
		g_SocketsMapsMutex.lock_shared();
		auto it = g_UDPAssociateMap.find(s);
		if (it != g_UDPAssociateMap.end()) {
			entryCopy = it->second; 
			associated = true;
		}
		g_SocketsMapsMutex.unlock_shared();
	}


	if (associated) {
		WSABUF destBuff;
		EncapsulateUDPPacket(&destBuff, (char *)buf, len, to);

		auto sended = Real_sendto(s, destBuff.buf, destBuff.len, 0, (const sockaddr*)&entryCopy.udpProxyAddr, sizeof(entryCopy.udpProxyAddr));
		free(destBuff.buf);
		
		return sended;
	}

	return Real_sendto(s, buf, len, flags, to, tolen);
}

int WINAPI Mine_WSASendTo(SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	const sockaddr* lpTo,
	int iTolen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	udp_association_entry_t entryCopy; 
	bool associated = false;

	if (!IsMultiCastAddr(lpTo)) { 
		g_SocketsMapsMutex.lock_shared();
		auto it = g_UDPAssociateMap.find(s);
		if (it != g_UDPAssociateMap.end()) {
			entryCopy = it->second; 
			associated = true;
		}
		g_SocketsMapsMutex.unlock_shared();
	}

	if (associated) {
	
	       if (dwBufferCount == 0 || lpBuffers == nullptr || lpBuffers->len == 0) {
	           return Real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
	       }

		WSABUF destBuff;
		EncapsulateUDPPacket(&destBuff, lpBuffers->buf, lpBuffers->len, lpTo);

		auto status = Real_WSASendTo(
			s,
			&destBuff, 
			1,         
			lpNumberOfBytesSent,
			0, 
			(const sockaddr*)(&entryCopy.udpProxyAddr),
			sizeof(entryCopy.udpProxyAddr),
			lpOverlapped,
			lpCompletionRoutine
		);

		free(destBuff.buf);
		return status;
	}

	return Real_WSASendTo(
		s,
		lpBuffers,
		dwBufferCount,
		lpNumberOfBytesSent,
		dwFlags,
		lpTo,
		iTolen,
		lpOverlapped,
		lpCompletionRoutine
	);
}

int WINAPI Mine_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
	auto received = Real_recvfrom(s, buf, len, flags, from, fromlen);

	if (received != SOCKET_ERROR && SocketExistsInUdpAssociationMap(s)) {
		//Encapsulated header is 10 bytes
		if (received < 10) {
			return SOCKET_ERROR;
		}

		ExtractSockAddr(buf, from);

		memmove(buf, &buf[10], received -= 10);
	};

	return received;
}

int WINAPI Mine_WSARecvFrom(SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	sockaddr* lpFrom,
	LPINT lpFromlen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	DWORD received = 0;
	if (lpNumberOfBytesRecvd == NULL)
		lpNumberOfBytesRecvd = &received;

	auto status = Real_WSARecvFrom(
		s,
		lpBuffers,
		dwBufferCount,
		lpNumberOfBytesRecvd,
		lpFlags,
		lpFrom,
		lpFromlen,
		lpOverlapped,
		lpCompletionRoutine
	);

	if (status == ERROR_SUCCESS && SocketExistsInUdpAssociationMap(s)) {
		//Encapsulated header is 10 bytes
		if (*lpNumberOfBytesRecvd < 10) {
			return SOCKET_ERROR;
		}

		ExtractSockAddr(lpBuffers->buf, lpFrom);

		memmove(lpBuffers->buf, &lpBuffers->buf[10], *lpNumberOfBytesRecvd -= 10);
	}

	return status;
}

void InitHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	AttachDnsHooks();
	DetourAttach((PVOID*)(&Real_WSAEventSelect), Mine_WSAEventSelect);
	DetourAttach((PVOID*)(&Real_ioctlsocket), Mine_ioctlsocket);
	DetourAttach((PVOID*)(&Real_connect), Mine_connect);
	DetourAttach((PVOID*)(&Real_bind), Mine_bind);
	DetourAttach((PVOID*)(&Real_closesocket), Mine_closesocket);
	DetourAttach((PVOID*)(&Real_sendto), Mine_sendto);
	DetourAttach((PVOID*)(&Real_recvfrom), Mine_recvfrom);
	DetourAttach((PVOID*)(&Real_WSASendTo), Mine_WSASendTo);
	DetourAttach((PVOID*)(&Real_WSARecvFrom), Mine_WSARecvFrom);
	DetourTransactionCommit();
}

void DestroyHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetachDnsHooks();
	DetourDetach((PVOID*)(&Real_WSAEventSelect), Mine_WSAEventSelect);
	DetourDetach((PVOID*)(&Real_ioctlsocket), Mine_ioctlsocket);
	DetourDetach((PVOID*)(&Real_connect), Mine_connect);
	DetourDetach((PVOID*)(&Real_bind), Mine_bind);
	DetourDetach((PVOID*)(&Real_closesocket), Mine_closesocket);
	DetourDetach((PVOID*)(&Real_sendto), Mine_sendto);
	DetourDetach((PVOID*)(&Real_recvfrom), Mine_recvfrom);
	DetourDetach((PVOID*)(&Real_WSASendTo), Mine_WSASendTo);
	DetourDetach((PVOID*)(&Real_WSARecvFrom), Mine_WSARecvFrom);
	DetourTransactionCommit();
}
