#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <detours/detours.h>
#include "proxy.h"
#include "browser_proxy.h"

namespace fs = std::filesystem;

extern "C" BOOL(__stdcall * Real_CreateProcessW)(LPCWSTR a0,
	LPWSTR a1,
	LPSECURITY_ATTRIBUTES a2,
	LPSECURITY_ATTRIBUTES a3,
	BOOL a4,
	DWORD a5,
	LPVOID a6,
	LPCWSTR a7,
	LPSTARTUPINFOW a8,
	LPPROCESS_INFORMATION a9) = CreateProcessW;

HMODULE OriginalDLL;
uintptr_t OrignalDWriteCreateFactory;
uintptr_t OrignalGetFileVersionInfoSizeW;
uintptr_t OrignalGetFileVersionInfoW;
uintptr_t OrignalVerQueryValueW;

bool EndsWith(const std::wstring& fullString, const std::wstring& ending)
{
	if (ending.size() > fullString.size())
		return false;

	return fullString.compare(fullString.size() - ending.size(), ending.size(), ending) == 0;
}

BOOL __stdcall Mine_CreateProcessW(LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	;
	WCHAR path[MAX_PATH];
	GetModuleFileNameW(NULL, path, MAX_PATH);

	std::vector<std::wstring> files = {
		L"proxy.txt",
		L"force-proxy.dll",
		L"DWrite.dll"
	};

	if (lpApplicationName != NULL) {
		auto targetAppName = std::wstring(lpApplicationName);
		auto currentPath = std::wstring(path);

		if (EndsWith(targetAppName, L"Discord.exe") && targetAppName != currentPath) {
			auto currentDir = fs::path(currentPath).parent_path();
			auto targetDir = fs::path(targetAppName).parent_path();

			// Use the non-throwing overloads: an exception escaping this hook
			// would terminate the updater. A failed copy only means the new
			// version starts without the proxy; the launch itself must proceed.
			for (const auto& file : files) {
				std::error_code error;
				const auto source = currentDir / file;
				if (fs::exists(source, error) && !error) {
					fs::copy(source, targetDir / file, fs::copy_options::overwrite_existing, error);
				}
			}
		}
	}

	return Real_CreateProcessW(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);
}

// Directory containing this DLL (beside Discord.exe), independent of the
// process's current working directory.
fs::path ModuleDirectory(HMODULE module)
{
	std::wstring path(MAX_PATH, L'\0');
	for (;;) {
		const DWORD length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
		if (length == 0) return {};
		if (length < path.size()) {
			path.resize(length);
			return fs::path(path).parent_path();
		}
		path.resize(path.size() * 2);
	}
}

void LoadForceProxy(HMODULE module)
{
	const auto directory = ModuleDirectory(module);
	std::ifstream file(directory / L"proxy.txt");
	std::string line;

	while (file.is_open() && getline(file, line)) {
		if (!line.empty() && line.back() == '\r') line.pop_back();
		std::stringstream ss(line);

		std::string key, value;
		if (getline(ss, key, '=') && getline(ss, value)) {
			SetEnvironmentVariableA(key.c_str(), value.c_str());
		}
	}

	const auto forceProxy = directory.empty() ? fs::path(L"force-proxy.dll") : directory / L"force-proxy.dll";
	if (LoadLibraryW(forceProxy.c_str()) == NULL) {
		char text[MAX_PATH];
		_snprintf_s(text, sizeof(text), "Cannot load force-proxy.dll. Error code: %d", GetLastError());
		MessageBoxA(0, text, "Proxy", MB_ICONERROR);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	char path[MAX_PATH];
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		CopyMemory(path + GetSystemDirectoryA(path, MAX_PATH - 12), "\\DWrite.dll", 13);
		OriginalDLL = LoadLibraryA(path);
		if (OriginalDLL == NULL)
		{
			MessageBoxA(0, "Cannot load original version.dll", "Proxy", MB_ICONERROR);
			MessageBoxA(0, path, "Proxy", MB_ICONERROR);
			ExitProcess(0);
		}
		OrignalDWriteCreateFactory = (uintptr_t)GetProcAddress(OriginalDLL, "DWriteCreateFactory");

		LoadForceProxy(hModule);
		AttachBrowserProxy();
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach((PVOID *)(&Real_CreateProcessW), Mine_CreateProcessW);
		DetourTransactionCommit();

		break;
	}
	case DLL_PROCESS_DETACH:
	{
		DetachBrowserProxy();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach((PVOID*)(&Real_CreateProcessW), Mine_CreateProcessW);
		DetourTransactionCommit();

		FreeLibrary(OriginalDLL);

		break;
	}
	}
	return TRUE;
}