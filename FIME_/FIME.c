#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

BOOL IsX86(HANDLE pid);
BOOL isInjected(DWORD pid, LPCTSTR moduleName, PBYTE* pDllBaseAddress);
BOOL injectDll(DWORD pid, LPCTSTR path);
BOOL uninjectDll(DWORD pid, PBYTE pDllBaseAddress);

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hWnd, message, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int cmdShow)
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
    {
        MessageBox(NULL, TEXT("No permission OR Final Fantasy XIV is not running"), TEXT("FIMEC"), 0);
        return 1;
    }

    if (GetWindowThreadProcessId(hFFXIV, &pid) == 0 || pid == 0)
    {
        MessageBox(NULL, TEXT("No permission OR Final Fantasy XIV is not running"), TEXT("FIMEC"), 0);
        return 1;
    }

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProc == NULL)
    {
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc == NULL)
        {
            MessageBox(NULL, TEXT("No permission OR Final Fantasy XIV is not running"), TEXT("FIMEC"), 0);
            return 1;
        }
    }

    isX86 = IsX86(hProc);
    CloseHandle(hProc);

    hModule = GetModuleHandle(NULL);
    if (hModule == NULL)
    {
        MessageBox(NULL, TEXT("No permission OR Final Fantasy XIV is not running"), TEXT("FIMEC"), 0);
        return 1;
    }
    
    if (isInjected(pid, isX86 ? TEXT("FIME32.dll") : TEXT("FIME64.dll"), &pDllBaseAddress))
    {
        if (!uninjectDll(pid, pDllBaseAddress))
            MessageBox(NULL, TEXT("un-injection failed."), TEXT("FIMEC"), 0);
        else
            MessageBox(NULL, TEXT("un-injected"), TEXT("FIMEC"), 0);

    }
    else
    {
        GetModuleFileName(hModule, path, sizeof(path));

        lstrcpy(wcsrchr(path, TEXT('\\')) + 1, isX86 ? TEXT("FIME32.dll") : TEXT("FIME64.dll"));

        if (!injectDll(pid, path))
            MessageBox(NULL, TEXT("injection failed."), TEXT("FIMEC"), 0);
        else
            MessageBox(NULL, TEXT("injected"), TEXT("FIMEC"), 0);
    }
    
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

BOOL isInjected(DWORD pid, LPCTSTR moduleName, PBYTE* pDllBaseAddress)
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
            if (!lstrcmp(snapEntry.szModule, moduleName))
            {
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
    BOOL result = FALSE;

    HMODULE hKernel32;
    LPTHREAD_START_ROUTINE lpLoadLibrary;

    LPVOID pBuff;
    DWORD pBuffSize;

    HANDLE hProcess;
    HANDLE hThread;

    DWORD exitCode;
    
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
                result = GetExitCodeThread(hThread, &exitCode) && exitCode;

                CloseHandle(hThread);
            }
        }

        VirtualFreeEx(hProcess, pBuff, 0, MEM_RELEASE);
    }

    CloseHandle(hProcess);

    return result;
}

BOOL uninjectDll(DWORD pid, PBYTE pDllBaseAddress)
{
    BOOL result = FALSE;

    HMODULE hKernel32;
    LPTHREAD_START_ROUTINE lpFreeLibrary;

    HANDLE hProcess;
    HANDLE hThread;

    DWORD exitCode;

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
        result = GetExitCodeThread(hThread, &exitCode) && exitCode;

        CloseHandle(hThread);
    }

    CloseHandle(hProcess);

    return result;
}
