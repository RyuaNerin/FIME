#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

#include "resource.h"

void extractDLL(LPCTSTR path);
int fileExists(LPCTSTR path);
BOOL injectDll(DWORD pid, LPCTSTR path);

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int cmdShow)
{
    HMODULE hModule;
    TCHAR path[MAX_PATH] = { 0, };
    STARTUPINFO si = { 0, };
    PROCESS_INFORMATION pi = { 0, };

    si.cb = sizeof(STARTUPINFO);

    hModule = GetModuleHandle(NULL);
    if (hModule == NULL)
        return 0;

    GetModuleFileName(hModule, path, sizeof(path));

    lstrcpy(wcsrchr(path, TEXT('\\')) + 1, TEXT("FIME") TEXT(FIME_ARCH) TEXT(".dll"));

    if (!fileExists(path))
        extractDLL(path);

    lstrcpy(wcsrchr(path, TEXT('\\')) + 1, TEXT("ffxiv") TEXT(FIME_DX11) TEXT(".exe_"));

    if (!CreateProcess(path, lpCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return 0;

    Sleep(5000);

    injectDll(pi.dwProcessId, path);

    return 0;
}

void extractDLL(LPCTSTR path)
{
    HRSRC findRes;
    HGLOBAL hRes;
    LPVOID data;
    DWORD dataSize;
    HANDLE hFile;
    DWORD written;

    findRes = FindResource(NULL, MAKEINTRESOURCE(FIME_DLL_DATA), RT_RCDATA);
    if (findRes)
    {
        hRes = LoadResource(NULL, findRes);
        if (hRes)
        {
            data = LockResource(hRes);

            if (data)
            {
                dataSize = SizeofResource(NULL, findRes);

                hFile = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
                if (hFile)
                {
                    WriteFile(hFile, data, dataSize, &written, NULL);
                    CloseHandle(hFile);
                }
            }
        }
    }

}

int fileExists(LPCTSTR path)
{
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}


BOOL injectDll(DWORD pid, LPCTSTR path)
{
    BOOL res = FALSE;

    HMODULE hKernel32;
    LPTHREAD_START_ROUTINE lpLoadLibrary;

    LPVOID pBuff;
    DWORD pBuffSize;

    HANDLE hProcess;
    HANDLE hThread;

    hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernel32 == NULL)
        return FALSE;

    lpLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (lpLoadLibrary == NULL)
        return FALSE;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
        return FALSE;

    pBuffSize = (lstrlen(path) + 1) * sizeof(TCHAR);
    pBuff = VirtualAllocEx(hProcess, NULL, pBuffSize, MEM_COMMIT, PAGE_READWRITE);
    if (pBuff != NULL)
    {
        if (WriteProcessMemory(hProcess, pBuff, (LPVOID)path, pBuffSize, NULL))
        {
            hThread = CreateRemoteThread(hProcess, NULL, 0, lpLoadLibrary, pBuff, 0, NULL);
            if (hThread != NULL)
            {
                WaitForSingleObject(hThread, INFINITE);
                res = TRUE;
            }
            CloseHandle(hThread);
        }
        VirtualFreeEx(hProcess, pBuff, pBuffSize, MEM_RELEASE);
    }

    CloseHandle(hProcess);

    return res;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hWnd, message, wParam, lParam);
}
