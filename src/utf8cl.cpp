#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <detours.h>

std::wstring quoteIfNecessary(const wchar_t *s)
{
	if (wcschr(s, L' ') == NULL)
	{
		return s;
	}

	std::wstring qs(L"\"");
	qs.append(s);
	qs.push_back(L'\"');
	return qs;
}

bool BuildCommandLine(std::vector<WCHAR> &commandLineData)
{
	int nArgs;
	auto args = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (args == NULL)
	{
		return false;
	}

	std::wstring commandLine;

	for (int i = 1; i < nArgs; ++i)
	{
		if (!commandLine.empty())
		{
			commandLine.push_back(L' ');
		}

		commandLine.append(quoteIfNecessary(args[i]));
	}

	LocalFree(args);

	commandLineData.resize(commandLine.size() + 1);
	std::copy(commandLine.begin(), commandLine.end(), commandLineData.begin());
	return true;
}

bool GetHookDllFileName(CHAR *pszDllPath, int size)
{
	CHAR szTmpPath[MAX_PATH];
	CHAR szExePath[MAX_PATH];
	CHAR *pszFilePart = NULL;

	if (!GetModuleFileNameA(NULL, szTmpPath, ARRAYSIZE(szTmpPath)))
	{
		return false;
	}

	if (!GetFullPathNameA(szTmpPath, ARRAYSIZE(szExePath), szExePath, &pszFilePart) ||
		pszFilePart == NULL)
	{
		return false;
	}

	strcpy_s(pszFilePart, szExePath + ARRAYSIZE(szExePath) - pszFilePart, "utf8hook32.dll");
	strcpy_s(pszDllPath, size, szExePath);
	return true;
}

#ifdef _CONSOLE
int main(int argc, char *argv[])
#else
int CALLBACK wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
#endif
{
	std::vector<WCHAR> commandLine;
	if (!BuildCommandLine(commandLine))
	{
		return 1;
	}

	CHAR szDllPath[MAX_PATH];
	if (!GetHookDllFileName(szDllPath, ARRAYSIZE(szDllPath)))
	{
		return 2;
	}

	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	if (!DetourCreateProcessWithDllExW(NULL, commandLine.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, NULL, szDllPath, NULL))
	{
		return 3;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}
