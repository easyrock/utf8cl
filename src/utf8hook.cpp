#include <windows.h>
#include <detours.h>
#include <minhook.h>
#include <wchar.h>

CHAR g_myModulePath[MAX_PATH];
bool g_isCL = false;
bool g_hasLoadedC1XX = false;

BOOL (WINAPI * Real_CreateProcessA)(LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

BOOL (WINAPI * Real_CreateProcessW)(LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation);

int (WINAPI * Real_MultiByteToWideChar)(UINT CodePage,
	DWORD dwFlags,
	LPCSTR lpMultiByteStr,
	int cbMultiByte,
	LPWSTR lpWideCharStr,
	int cchWideChar);

HMODULE (WINAPI * Real_LoadLibraryW)(LPCWSTR lpFileName);

BOOL WINAPI Mine_CreateProcessA(LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
	// hook every child process
	return DetourCreateProcessWithDllExA(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		g_myModulePath,
		Real_CreateProcessA);
}

BOOL WINAPI Mine_CreateProcessW(LPCWSTR lpApplicationName,
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
	// hook every child process
	return DetourCreateProcessWithDllExW(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		g_myModulePath,
		Real_CreateProcessW);
}

HMODULE WINAPI Mine_LoadLibraryW(LPCWSTR lpFileName)
{
	// CL loads C1XX.DLL with LoadLibraryW()
	auto retval = Real_LoadLibraryW(lpFileName);
	if (retval != NULL)
	{
		if (!g_hasLoadedC1XX)
		{
			auto len = wcslen(lpFileName);
			if (len >= 8 && _wcsicmp(lpFileName + len - 8, L"c1xx.dll") == 0)
			{
				g_hasLoadedC1XX = true;
			}
		}
	}
	return retval;
}

int WINAPI Mine_MultiByteToWideChar(UINT CodePage,
	DWORD dwFlags,
	LPCSTR lpMultiByteStr,
	int cbMultiByte,
	LPWSTR lpWideCharStr,
	int cchWideChar)
{
	if (g_isCL && g_hasLoadedC1XX)
	{
		// MAGIC
		if (CodePage == 0 && dwFlags == MB_ERR_INVALID_CHARS)
		{
			CodePage = 65001;
		}
	}

	return Real_MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

BOOL ProcessAttach(HMODULE hDll)
{
	// get our module path
	if (!GetModuleFileNameA(hDll, g_myModulePath, ARRAYSIZE(g_myModulePath)))
	{
		return FALSE;
	}

	// get running executable file name;
	CHAR szExePath[MAX_PATH];
	if (!GetModuleFileNameA(NULL, szExePath, ARRAYSIZE(szExePath)))
	{
		return FALSE;
	}

	// is that CL ?
	auto len = strlen(szExePath);
	if (len >= 6 && _stricmp(szExePath + len - 6, "cl.exe") == 0)
	{
		g_isCL = true;
	}

	if (MH_Initialize() != MH_OK)
	{
		return FALSE;
	}

	MH_CreateHook(CreateProcessA, Mine_CreateProcessA, reinterpret_cast<LPVOID*>(&Real_CreateProcessA));
	MH_CreateHook(CreateProcessW, Mine_CreateProcessW, reinterpret_cast<LPVOID*>(&Real_CreateProcessW));
	MH_CreateHook(LoadLibraryW, Mine_LoadLibraryW, reinterpret_cast<LPVOID*>(&Real_LoadLibraryW));
	MH_CreateHook(MultiByteToWideChar, Mine_MultiByteToWideChar, reinterpret_cast<LPVOID*>(&Real_MultiByteToWideChar));

	MH_EnableHook(CreateProcessA);
	MH_EnableHook(CreateProcessW);
	MH_EnableHook(LoadLibraryW);
	MH_EnableHook(MultiByteToWideChar);

	return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
	MH_RemoveHook(CreateProcessA);
	MH_RemoveHook(CreateProcessW);
	MH_RemoveHook(LoadLibraryW);
	MH_RemoveHook(MultiByteToWideChar);

	MH_Uninitialize();
	return TRUE;
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
	if (DetourIsHelperProcess())
	{
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DetourRestoreAfterWith();
		return ProcessAttach(hModule);
	}

	if (dwReason == DLL_PROCESS_DETACH)
	{
		return ProcessDetach(hModule);
	}

	return TRUE;
}
