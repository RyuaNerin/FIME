#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <winhttp.h>
#include <regex>

#include "resource.h"

#define PROJECT_NAME            L"FIME"

// 2016.11.21 (3.15)

#ifdef _WIN64
#define FFXIV_PROCESS_NAME      L"ffxiv_dx11.exe"
#define FFXIV_EXE_FILE_SIZE     23937264
#define FFXIV_BASE_MODULE_SIZE  0x01A40000
#define FFXIV_MEMORY_OFFSET     0x0026AEA1

BYTE newBytes[] = { 0xEB };
BYTE chkBytes[] = { 0xEB, 0x1B, 0x48, 0x8B, 0x86, 0x90, 0x31, 0x00, 0x00, 0x0F, 0xBE, 0xD1, 0x48, 0x8D, 0x8E };
BYTE oldBytes[] = { 0x74, 0x1B, 0x48, 0x8B, 0x86, 0x90, 0x31, 0x00, 0x00, 0x0F, 0xBE, 0xD1, 0x48, 0x8D, 0x8E };
#else
#define FFXIV_PROCESS_NAME      L"ffxiv.exe"
#define FFXIV_EXE_FILE_SIZE     16943856
#define FFXIV_BASE_MODULE_SIZE  0x012F5000
#define FFXIV_MEMORY_OFFSET     0x001EE0B3

BYTE newBytes[] = { 0xEB };
BYTE chkBytes[] = { 0xEB, 0x1C, 0x8B, 0x93, 0x5C, 0x22, 0x00, 0x00, 0x8B, 0x52, 0x2C, 0x0F, 0xBE, 0xC0, 0x50 };
BYTE oldBytes[] = { 0x74, 0x1C, 0x8B, 0x93, 0x5C, 0x22, 0x00, 0x00, 0x8B, 0x52, 0x2C, 0x0F, 0xBE, 0xC0, 0x50 };
#endif

#define MESSAGEBOX_INFOMATION(MSG)  MessageBox(NULL, TEXT(MSG), PROJECT_NAME, MB_OK | MB_ICONINFORMATION)
#define MESSAGEBOX_ASTERISK(MSG)    MessageBox(NULL, TEXT(MSG), PROJECT_NAME, MB_OK | MB_ICONASTERISK)

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hWnd, message, wParam, lParam);
}

DWORD checkLatestRelease(LPWSTR url);
BOOL getFFXIVModule(DWORD pid, PBYTE* modBaseAddr, DWORD* modBaseSize);
DWORD getFileSize(LPCWSTR path);
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int cmdShow)
{
    TCHAR filePath[MAX_PATH];

    switch (checkLatestRelease(filePath))
    {
        case 0: break;
        case 1:
            MESSAGEBOX_INFOMATION("최신 버전이 릴리즈 되었습니다!");
            ShellExecute(NULL, NULL, filePath, NULL, NULL, SW_SHOW);
            return 1;
        case -1:
            if (MessageBox(NULL, L"최신 릴리즈 정보를 가져오지 못하였습니다.\n계속 실행하시겠습니까?", PROJECT_NAME, MB_YESNO | MB_ICONQUESTION) == IDNO)
                return -1;
        case -2:
            MESSAGEBOX_ASTERISK("최신 릴리즈 정보를 가져오는 중 오류가 발생하였습니다.");
            return -1;
    }

    BOOL res = FALSE;

    PROCESSENTRY32 entry = { 0, };
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        MESSAGEBOX_ASTERISK("관리자 권한으로 실행시켜주세요!");
        return 1;
    }

    DWORD pid;
    HANDLE hProcess;

    PBYTE modBaseAddr;
    DWORD modBaseSize;

    BYTE buff[sizeof(oldBytes)];

    if (Process32First(snapshot, &entry))
    {
        while (Process32Next(snapshot, &entry))
        {
            if (lstrcmp(entry.szExeFile, FFXIV_PROCESS_NAME) == 0)
            {
                pid = entry.th32ProcessID;

                if (getFFXIVModule(pid, &modBaseAddr, &modBaseSize))
                {
                    if (modBaseSize != FFXIV_BASE_MODULE_SIZE)
                    {
                        MESSAGEBOX_ASTERISK("지원되지 않는 클라이언트 버전입니다!");
                        continue;
                    }

                    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                    if (hProcess == NULL)
                    {
                        MESSAGEBOX_ASTERISK("관리자 권한으로 실행시켜주세요!");
                        return 1;
                    }

                    if (GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH) == 0)
                    {
                        MESSAGEBOX_ASTERISK("관리자 권한으로 실행시켜주세요!");
                        return 1;
                    }

                    if (getFileSize(filePath) != FFXIV_EXE_FILE_SIZE)
                    {
                        MESSAGEBOX_ASTERISK("지원되지 않는 클라이언트 버전입니다!");
                        continue;
                    }

                    ReadProcessMemory(hProcess, modBaseAddr + FFXIV_MEMORY_OFFSET, buff, sizeof(oldBytes), NULL);
                    if (memcmp(buff, chkBytes, sizeof(chkBytes)) == 0)
                    {
                        res = TRUE;
                    }
                    else
                    {
                        if (memcmp(buff, oldBytes, sizeof(oldBytes)) != 0)
                        {
                            MESSAGEBOX_ASTERISK("지원되지 않는 클라이언트 버전입니다!");
                        }
                        else
                        {
                            WriteProcessMemory(hProcess, modBaseAddr + FFXIV_MEMORY_OFFSET, newBytes, sizeof(newBytes), NULL);
                            res = TRUE;
                        }
                    }

                    CloseHandle(hProcess);
                }
            }
        }
    }

    CloseHandle(snapshot);

    if (res)
        MESSAGEBOX_INFOMATION("성공적으로 적용했습니다!");

    return 0;
}

DWORD checkLatestRelease(LPWSTR lpUrl)
{
#define HOST    L"api.github.com"
#define PATH    L"/repos/RyuaNerin/FIME/releases/latest"

    DWORD result = -1;

    BOOL      bResults;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    CHAR    buf[40960] = { 0, };
    DWORD   read;

    hSession = WinHttpOpen(PROJECT_NAME, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession)
        hConnect = WinHttpConnect(hSession, HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, NULL);
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (bResults)
        bResults = WinHttpReadData(hRequest, (LPVOID)buf, sizeof(buf), &read);
    if (bResults)
    {
        result = -2;

        std::string str(buf);
        std::smatch match;

        std::regex regex_tag("\"tag_name\"[ \\t]*:[ \\t]*\"([^\"]+)\"");
        if (std::regex_search(str, match, regex_tag))
        {
            if (match[1].compare(VERSION_STR) == 0)
            {
                result = 0;
            }
            else
            {
                std::regex regex_url("\"html_url\"[ \\t]*:[ \\t]*\"([^\"]+)\"");
                if (std::regex_search(str, match, regex_url))
                {
                    result = 1;

                    std::string url = match[1];
                    std::wstring wurl = L"";

                    wurl.assign(url.begin(), url.end());

                    wurl.copy(lpUrl, wurl.length(), 0);
                }
            }
        }
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}

DWORD getFileSize(LPCWSTR path)
{
    HANDLE hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return -1;

    DWORD size = GetFileSize(hFile, NULL);

    CloseHandle(hFile);
    return size;
}

BOOL getFFXIVModule(DWORD pid, PBYTE* modBaseAddr, DWORD* modBaseSize)
{
    BOOL res = FALSE;

    MODULEENTRY32 snapEntry = { 0 };
    snapEntry.dwSize = sizeof(MODULEENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot)
    {
        if (Module32First(hSnapshot, &snapEntry))
        {
            do
            {
                if (lstrcmp(snapEntry.szModule, FFXIV_PROCESS_NAME) == 0)
                {
                    *modBaseAddr = snapEntry.modBaseAddr;
                    *modBaseSize = snapEntry.modBaseSize;
                    res = TRUE;
                    break;
                }
            } while (Module32Next(hSnapshot, & snapEntry));
        }
        CloseHandle(hSnapshot);
    }

    return res;
}
