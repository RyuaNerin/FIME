#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

BOOL IsX86(HANDLE pid);
BOOL isInjected(DWORD pid, LPCTSTR path, PBYTE* pDllBaseAddress);
BOOL injectDll(DWORD pid, LPCTSTR path);
BOOL uninjectDll(DWORD pid, LPCTSTR path, PBYTE pDllBaseAddress);

#ifdef _UNICODE
#define printf_s    wprintf_s
#define lstrrchr    wcsrchr
#else
#define lstrrchr    strrchr
#endif

int main(void)
{
    HWND hFFXIV;
    DWORD pid;
    HANDLE hProc;

    BOOL isX86;
    HMODULE hModule;
    TCHAR path[MAX_PATH] = { 0, };
    PBYTE pDllBaseAddress;

    hFFXIV = FindWindow(TEXT("FFXIVGAME"), NULL);
    if (hFFXIV == NULL)
        return 0;

    if (GetWindowThreadProcessId(hFFXIV, &pid) == 0 || pid == 0)
        return 0;

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc == NULL)
    {
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc == NULL)
            return 0;
    }

    isX86 = IsX86(hProc);
    CloseHandle(hProc);

    hModule = GetModuleHandle(NULL);
    if (hModule == NULL)
        return 0;

    GetModuleFileName(hModule, path, sizeof(path));
    
    lstrcpy(lstrrchr(path, TEXT('\\')) + 1, isX86 ? TEXT("FIME32.dll") : TEXT("FIME64.dll"));
    
    if (isInjected(pid, path, &pDllBaseAddress))
    {
        if (!uninjectDll(pid, path, pDllBaseAddress))
            return 0;

        printf_s(TEXT("uninjected\n"));
    }
    else
    {
        if (!injectDll(pid, path))
            return 0;

        printf_s(TEXT("injected\n"));
    }

    system("pause");
    
    return 0;
}

typedef BOOL(WINAPI *D_ISWOW64PROCESS)(HANDLE, PBOOL);
BOOL IsX86(HANDLE pid)
{
    D_ISWOW64PROCESS fnIsWow64Process;
    BOOL b = FALSE;

    fnIsWow64Process = (D_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
    if (fnIsWow64Process == NULL)
        return FALSE;

    return fnIsWow64Process(pid, &b) && b;
}

BOOL isInjected(DWORD pid, LPCTSTR path, PBYTE* pDllBaseAddress)
{
    BOOL res = FALSE;

    MODULEENTRY32 snapEntry = { 0 };
    HANDLE hSnapshot;

    snapEntry.dwSize = sizeof(MODULEENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == NULL)
        return FALSE;

    if (Module32First(hSnapshot, &snapEntry))
    {
        do
        {
            if (!lstrcmp(snapEntry.szExePath, path))
            {
                printf_s(TEXT("%s\n"), snapEntry.szModule);
                *pDllBaseAddress = snapEntry.modBaseAddr;
                res = TRUE;
                break;
            }
        } while (Module32Next(hSnapshot, & snapEntry));
    }
    CloseHandle(hSnapshot);

    return res;
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

#if _UNICODE
    lpLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
#else
    lpLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
#endif
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

BOOL uninjectDll(DWORD pid, LPCTSTR path, PBYTE pDllBaseAddress)
{
    BOOL result = FALSE;

    HMODULE hKernel32;
    LPTHREAD_START_ROUTINE lpFreeLibrary;

    HANDLE hProcess;
    HANDLE hThread;

    hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernel32 == NULL)
        return FALSE;

    lpFreeLibrary = (LPTHREAD_START_ROUTINE)(GetProcAddress(hKernel32, "FreeLibrary"));
    if (lpFreeLibrary == NULL)
        return FALSE;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
        return FALSE;

    hThread = CreateRemoteThread(hProcess, NULL, 0, lpFreeLibrary, (PVOID)pDllBaseAddress, 0, NULL);
    if (hThread != NULL)
    {
        WaitForSingleObject(hThread, INFINITE);
        result = TRUE;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return result;
}
