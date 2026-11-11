#include "stdafx.h"
#include "dns_hooks.h"
#include <atomic>
#include <mutex>

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

// Overlapped UDP operations on associated sockets complete after the hook
// returns. Their state is kept until the completion is observed through a
// completion routine, WSAGetOverlappedResult, or an I/O completion port.
namespace {
BOOL(WINAPI* Real_GetQueuedCompletionStatus)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD) = GetQueuedCompletionStatus;
BOOL(WINAPI* Real_GetQueuedCompletionStatusEx)(HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL) = GetQueuedCompletionStatusEx;
BOOL(WSAAPI* Real_WSAGetOverlappedResult)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD) = WSAGetOverlappedResult;

struct PendingOverlapped {
	SOCKET socket = INVALID_SOCKET;
	bool isSend = false;
	char* sendBuffer = nullptr;            // Encapsulated datagram; must outlive the send.
	std::vector<WSABUF> recvBuffers;       // Caller's buffers for in-place decapsulation.
	sockaddr* from = nullptr;
	LPINT fromLen = nullptr;
	LPWSAOVERLAPPED_COMPLETION_ROUTINE routine = nullptr;
	bool done = false;                     // Already adjusted (completed synchronously).
	DWORD rawBytes = 0;
	DWORD bytes = 0;
};

std::mutex g_OverlappedMutex;
std::map<LPWSAOVERLAPPED, PendingOverlapped> g_PendingOverlapped;
std::atomic<size_t> g_PendingOverlappedCount{ 0 };

void RegisterOverlapped(LPWSAOVERLAPPED overlapped, PendingOverlapped op)
{
	std::lock_guard<std::mutex> lock(g_OverlappedMutex);
	auto it = g_PendingOverlapped.find(overlapped);
	if (it != g_PendingOverlapped.end()) {
		// The caller may only reuse an OVERLAPPED after the previous operation
		// completed, so its buffer is no longer in use.
		free(it->second.sendBuffer);
		it->second = std::move(op);
		return;
	}
	g_PendingOverlapped.emplace(overlapped, std::move(op));
	++g_PendingOverlappedCount;
}

// Applies the SOCKS5 adjustment for a completed operation. Returns false when
// the OVERLAPPED is not one of ours (or the entry is stale).
bool FinishOverlapped(LPWSAOVERLAPPED overlapped, bool success, DWORD raw, bool erase, bool fromRoutine,
	DWORD* adjusted, LPWSAOVERLAPPED_COMPLETION_ROUTINE* routine)
{
	if (!overlapped || g_PendingOverlappedCount.load() == 0) return false;

	std::lock_guard<std::mutex> lock(g_OverlappedMutex);
	auto it = g_PendingOverlapped.find(overlapped);
	if (it == g_PendingOverlapped.end()) return false;
	auto& op = it->second;

	auto eraseEntry = [&]() {
		free(op.sendBuffer);
		g_PendingOverlapped.erase(it);
		--g_PendingOverlappedCount;
	};

	if (op.done) {
		// A synchronously completed entry that nobody consumed may be stale if
		// the OVERLAPPED was reused for an unrelated operation.
		if (!fromRoutine && raw != op.rawBytes && raw != op.bytes) {
			eraseEntry();
			return false;
		}
	} else if (success) {
		op.rawBytes = raw;
		if (op.isSend) {
			op.bytes = raw >= 10 ? raw - 10 : 0;
		} else {
			op.bytes = raw;
			DecapsulateUDPBuffers(op.recvBuffers.data(), static_cast<DWORD>(op.recvBuffers.size()),
				&op.bytes, op.from, op.fromLen);
		}
		op.done = true;
		overlapped->InternalHigh = op.bytes;
	}

	if (adjusted) *adjusted = success ? op.bytes : raw;
	if (routine) *routine = op.routine;

	if (op.done) {
		free(op.sendBuffer);
		op.sendBuffer = nullptr;
	}
	if (erase) eraseEntry();
	return true;
}

void CALLBACK OverlappedCompletionThunk(DWORD error, DWORD transferred, LPWSAOVERLAPPED overlapped, DWORD flags)
{
	LPWSAOVERLAPPED_COMPLETION_ROUTINE routine = nullptr;
	DWORD adjusted = transferred;
	FinishOverlapped(overlapped, error == 0, transferred, true, true, &adjusted, &routine);
	if (routine) routine(error, adjusted, overlapped, flags);
}

BOOL WINAPI Mine_GetQueuedCompletionStatus(HANDLE port, LPDWORD bytes, PULONG_PTR key, LPOVERLAPPED* overlapped, DWORD timeout)
{
	const BOOL ok = Real_GetQueuedCompletionStatus(port, bytes, key, overlapped, timeout);
	if (overlapped && *overlapped && g_PendingOverlappedCount.load()) {
		const DWORD lastError = GetLastError();
		DWORD adjusted = bytes ? *bytes : 0;
		if (FinishOverlapped(reinterpret_cast<LPWSAOVERLAPPED>(*overlapped), ok != FALSE, adjusted, true, false, &adjusted, nullptr) && ok && bytes)
			*bytes = adjusted;
		SetLastError(lastError);
	}
	return ok;
}

BOOL WINAPI Mine_GetQueuedCompletionStatusEx(HANDLE port, LPOVERLAPPED_ENTRY entries, ULONG count, PULONG removed, DWORD timeout, BOOL alertable)
{
	const BOOL ok = Real_GetQueuedCompletionStatusEx(port, entries, count, removed, timeout, alertable);
	if (ok && removed && g_PendingOverlappedCount.load()) {
		for (ULONG i = 0; i < *removed; ++i) {
			auto overlapped = reinterpret_cast<LPWSAOVERLAPPED>(entries[i].lpOverlapped);
			// Internal holds the NTSTATUS of the operation; 0 is success.
			const bool success = overlapped && entries[i].Internal == 0;
			DWORD adjusted = entries[i].dwNumberOfBytesTransferred;
			if (FinishOverlapped(overlapped, success, adjusted, true, false, &adjusted, nullptr) && success)
				entries[i].dwNumberOfBytesTransferred = adjusted;
		}
	}
	return ok;
}

BOOL WSAAPI Mine_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED overlapped, LPDWORD transferred, BOOL wait, LPDWORD flags)
{
	const BOOL ok = Real_WSAGetOverlappedResult(s, overlapped, transferred, wait, flags);
	if (g_PendingOverlappedCount.load() && transferred) {
		const int lastError = WSAGetLastError();
		// Still in progress: leave the entry for the later call.
		if (ok || lastError != WSA_IO_INCOMPLETE) {
			DWORD adjusted = *transferred;
			if (FinishOverlapped(overlapped, ok != FALSE, adjusted, true, false, &adjusted, nullptr) && ok)
				*transferred = adjusted;
		}
		WSASetLastError(lastError);
	}
	return ok;
}
}

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

	if (to && !IsMultiCastAddr(to)) {
		g_SocketsMapsMutex.lock_shared();
		auto it = g_UDPAssociateMap.find(s);
		if (it != g_UDPAssociateMap.end()) {
			entryCopy = it->second; 
			associated = true;
		}
		g_SocketsMapsMutex.unlock_shared();
	}


	if (associated) {
		if (len < 0 || (len > 0 && buf == nullptr)) {
			WSASetLastError(WSAEFAULT);
			return SOCKET_ERROR;
		}

		WSABUF source = { static_cast<ULONG>(len), const_cast<char*>(buf) };
		WSABUF destBuff;
		if (!EncapsulateUDPBuffers(&destBuff, &source, 1, to)) {
			WSASetLastError(WSAENOBUFS);
			return SOCKET_ERROR;
		}

		auto sended = Real_sendto(s, destBuff.buf, destBuff.len, 0, (const sockaddr*)&entryCopy.udpProxyAddr, sizeof(entryCopy.udpProxyAddr));
		free(destBuff.buf);

		// Report the caller's payload size, not payload + SOCKS5 header.
		if (sended == SOCKET_ERROR) return SOCKET_ERROR;
		return sended >= 10 ? sended - 10 : 0;
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

	// A NULL destination means a connected socket; there is nothing to encapsulate for.
	if (lpTo && !IsMultiCastAddr(lpTo)) { 
		g_SocketsMapsMutex.lock_shared();
		auto it = g_UDPAssociateMap.find(s);
		if (it != g_UDPAssociateMap.end()) {
			entryCopy = it->second; 
			associated = true;
		}
		g_SocketsMapsMutex.unlock_shared();
	}

	if (associated) {

	       if (dwBufferCount == 0 || lpBuffers == nullptr) {
	           return Real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
	       }

		WSABUF destBuff;
		if (!EncapsulateUDPBuffers(&destBuff, lpBuffers, dwBufferCount, lpTo)) {
			WSASetLastError(WSAENOBUFS);
			return SOCKET_ERROR;
		}

		if (lpOverlapped) {
			// The encapsulated buffer must stay alive until the send completes;
			// register it before issuing the send so a completion racing on
			// another thread can find it.
			PendingOverlapped op;
			op.socket = s;
			op.isSend = true;
			op.sendBuffer = destBuff.buf;
			op.routine = lpCompletionRoutine;
			RegisterOverlapped(lpOverlapped, std::move(op));
		}

		DWORD sent = 0;
		auto status = Real_WSASendTo(
			s,
			&destBuff,
			1,
			&sent,
			0,
			(const sockaddr*)(&entryCopy.udpProxyAddr),
			sizeof(entryCopy.udpProxyAddr),
			lpOverlapped,
			lpOverlapped && lpCompletionRoutine ? OverlappedCompletionThunk : lpCompletionRoutine
		);

		if (!lpOverlapped) {
			free(destBuff.buf);
			if (status == 0 && lpNumberOfBytesSent) *lpNumberOfBytesSent = sent >= 10 ? sent - 10 : 0;
			return status;
		}

		if (status == 0) {
			// Completed now; a completion notification may still be queued.
			DWORD adjusted = sent;
			// If a completion port thread already consumed the entry, it stored
			// the adjusted count in InternalHigh.
			if (!FinishOverlapped(lpOverlapped, true, sent, false, false, &adjusted, nullptr))
				adjusted = static_cast<DWORD>(lpOverlapped->InternalHigh);
			if (lpNumberOfBytesSent) *lpNumberOfBytesSent = adjusted;
		} else if (WSAGetLastError() != WSA_IO_PENDING) {
			const int error = WSAGetLastError();
			FinishOverlapped(lpOverlapped, false, 0, true, false, nullptr, nullptr);
			WSASetLastError(error);
		}
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
	for (;;) {
		auto received = Real_recvfrom(s, buf, len, flags, from, fromlen);
		if (received == SOCKET_ERROR || !SocketExistsInUdpAssociationMap(s)) {
			return received;
		}

		WSABUF buffer = { static_cast<ULONG>(received), buf };
		DWORD bytes = static_cast<DWORD>(received);
		if (DecapsulateUDPBuffers(&buffer, 1, &bytes, from, fromlen)) {
			return static_cast<int>(bytes);
		}

		// Malformed or fragmented relay datagram: drop it. Non-blocking callers
		// get "try again"; blocking callers wait for the next datagram.
		if (SocketExistsInNonBlockingMap(s)) {
			WSASetLastError(WSAEWOULDBLOCK);
			return SOCKET_ERROR;
		}
	}
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
	if (!SocketExistsInUdpAssociationMap(s) || lpBuffers == nullptr || dwBufferCount == 0) {
		return Real_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags,
			lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
	}

	if (!lpOverlapped) {
		for (;;) {
			DWORD received = 0;
			auto status = Real_WSARecvFrom(s, lpBuffers, dwBufferCount, &received, lpFlags,
				lpFrom, lpFromlen, nullptr, nullptr);
			if (status != ERROR_SUCCESS) return status;

			if (DecapsulateUDPBuffers(lpBuffers, dwBufferCount, &received, lpFrom, lpFromlen)) {
				if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = received;
				return ERROR_SUCCESS;
			}

			// Drop malformed relay datagrams (see Mine_recvfrom).
			if (SocketExistsInNonBlockingMap(s)) {
				WSASetLastError(WSAEWOULDBLOCK);
				return SOCKET_ERROR;
			}
		}
	}

	// Overlapped: the data usually arrives after this call returns, so the
	// header is stripped when the completion is observed. Register first in
	// case the completion is dequeued on another thread before we return.
	PendingOverlapped op;
	op.socket = s;
	op.recvBuffers.assign(lpBuffers, lpBuffers + dwBufferCount);
	op.from = lpFrom;
	op.fromLen = lpFromlen;
	op.routine = lpCompletionRoutine;
	RegisterOverlapped(lpOverlapped, std::move(op));

	DWORD received = 0;
	auto status = Real_WSARecvFrom(s, lpBuffers, dwBufferCount, &received, lpFlags,
		lpFrom, lpFromlen, lpOverlapped,
		lpCompletionRoutine ? OverlappedCompletionThunk : nullptr);

	if (status == ERROR_SUCCESS) {
		DWORD adjusted = received;
		if (!FinishOverlapped(lpOverlapped, true, received, false, false, &adjusted, nullptr))
			adjusted = static_cast<DWORD>(lpOverlapped->InternalHigh);
		if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = adjusted;
	} else if (WSAGetLastError() != WSA_IO_PENDING) {
		const int error = WSAGetLastError();
		FinishOverlapped(lpOverlapped, false, 0, true, false, nullptr, nullptr);
		WSASetLastError(error);
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
	DetourAttach((PVOID*)(&Real_WSAGetOverlappedResult), Mine_WSAGetOverlappedResult);
	DetourAttach((PVOID*)(&Real_GetQueuedCompletionStatus), Mine_GetQueuedCompletionStatus);
	DetourAttach((PVOID*)(&Real_GetQueuedCompletionStatusEx), Mine_GetQueuedCompletionStatusEx);
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
	DetourDetach((PVOID*)(&Real_WSAGetOverlappedResult), Mine_WSAGetOverlappedResult);
	DetourDetach((PVOID*)(&Real_GetQueuedCompletionStatus), Mine_GetQueuedCompletionStatus);
	DetourDetach((PVOID*)(&Real_GetQueuedCompletionStatusEx), Mine_GetQueuedCompletionStatusEx);
	DetourTransactionCommit();
}
