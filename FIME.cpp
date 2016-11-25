#include <regex>
#include <memory>

#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <winhttp.h>

#include "resource.h"

#define PROJECT_NAME            L"FIME v" TEXT(VERSION_STR)

#define FFXIV_VERSION           L"v3.15, 2016.10.04.0000.0000(2167201, ex1:2016.09.21.0000.0000)"

typedef struct _FIME_PATCH
{
    const size_t Offset;
    const char* newBytes;
    const char* chkBytes;
    const char* oldBytes;
} FIME_PATCH;
typedef struct _FIME_CLIENT
{
    const wchar_t*      processName;
    const size_t        exeSize;
    const size_t        moduleSize;
    const FIME_PATCH    patches[3];
} FIME_CLIENT;

#if _WIN64
FIME_CLIENT FFXIVX64 = 
{
    L"ffxiv_dx11.exe",
    23937264,
    0x01A40000,
    {
        {
            0x0026AEA1,
            "\xEB",
            "\xEB\x1B\x48\x8B\x86\x90\x31\x00\x00\x0F\xBE\xD1\x48\x8D\x8E\x90\x31\x00\x00\xFF\x50\x58\xC6\x86",
            "\x74\x1B\x48\x8B\x86\x90\x31\x00\x00\x0F\xBE\xD1\x48\x8D\x8E\x90\x31\x00\x00\xFF\x50\x58\xC6\x86"
        },
        {
            0x008C8B32,
            "\xEB",
            "\xEB\x24\x48\x8B\x4E\x08\x48\x8B\x01\xFF\x50\x38\x8B\x96\x80\x04\x00\x00\x4C\x8B\x00\x48\x8B\xC8",
            "\x74\x24\x48\x8B\x4E\x08\x48\x8B\x01\xFF\x50\x38\x8B\x96\x80\x04\x00\x00\x4C\x8B\x00\x48\x8B\xC8"
        },
        { 0, }
    }
};
#endif

FIME_CLIENT FFXIVX32 =
{
    L"ffxiv_dx9.exe",
    16943856,
    0x012F5000,
    {
        {
            0x001EE0B3,
            "\xEB",
            "\xEB\x1C\x8B\x93\x5C\x22\x00\x00\x8B\x52\x2C\x0F\xBE\xC0\x50\x8D\x8B\x5C\x22\x00\x00\xFF\xD2\xC6",
            "\x74\x1C\x8B\x93\x5C\x22\x00\x00\x8B\x52\x2C\x0F\xBE\xC0\x50\x8D\x8B\x5C\x22\x00\x00\xFF\xD2\xC6"
        },
        {
            0x00710FC3,
            "\xEB",
            "\xEB\x20\x8B\x4E\x04\x8B\x11\x8B\x42\x1C\xFF\xD0\x8B\x8E\x9C\x03\x00\x00\x8B\x10\x8B\x52\x04\x51",
            "\x74\x20\x8B\x4E\x04\x8B\x11\x8B\x42\x1C\xFF\xD0\x8B\x8E\x9C\x03\x00\x00\x8B\x10\x8B\x52\x04\x51"
        },
        { 0, }
    }
};

enum RELEASE_RESULT : DWORD
{
    LATEST,
    NEW_RELEASE,
    NETWORK_ERROR,
    PARSING_ERROR
};

#define MESSAGEBOX_INFOMATION(MSG)  MessageBox(NULL, TEXT(MSG), PROJECT_NAME, MB_OK | MB_ICONINFORMATION)
#define MESSAGEBOX_ASTERISK(MSG)    MessageBox(NULL, TEXT(MSG), PROJECT_NAME, MB_OK | MB_ICONASTERISK)

RELEASE_RESULT checkLatestRelease(LPWSTR lpUrl, DWORD cbUrl);
BOOL getFFXIVModule(DWORD pid, LPCWSTR lpModuleName, PBYTE* modBaseAddr, DWORD* modBaseSize);
DWORD getFileSize(LPCWSTR path);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int cmdShow)
{
    WCHAR filePath[4096];

    switch (checkLatestRelease(filePath, sizeof(filePath)))
    {
        case LATEST:
            break;

        case NEW_RELEASE:
            MESSAGEBOX_INFOMATION("최신 버전이 릴리즈 되었습니다!");
            ShellExecute(NULL, NULL, filePath, NULL, NULL, SW_SHOWNORMAL);
            return 1;

        case NETWORK_ERROR:
            if (MessageBox(NULL, L"최신 릴리즈 정보를 가져오지 못하였습니다.\n계속 실행하시겠습니까?", PROJECT_NAME, MB_YESNO | MB_ICONQUESTION) == IDNO)
                return -1;

        case PARSING_ERROR:
            MESSAGEBOX_ASTERISK("최신 릴리즈 정보를 가져오는 중 오류가 발생하였습니다.");
            return -1;
    }

    PROCESSENTRY32 entry = { 0, };
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        MESSAGEBOX_ASTERISK("관리자 권한으로 실행시켜주세요!");
        return 1;
    }

    bool res = false;

    FIME_CLIENT* client;
    const FIME_PATCH* patch;

    DWORD pid;
    HANDLE hProcess;

    PBYTE modBaseAddr;
    DWORD modBaseSize;

    BYTE buff[64];

    if (Process32First(snapshot, &entry))
    {
        while (Process32Next(snapshot, &entry))
        {
            client = nullptr;

#if _WIN64
            if (lstrcmp(entry.szExeFile, FFXIVX64.processName) == 0)
                client = &FFXIVX64;
            else
#endif
            if (lstrcmp(entry.szExeFile, FFXIVX32.processName) == 0)
                client = &FFXIVX32;

            if (client != nullptr)
            {
                pid = entry.th32ProcessID;

                if (getFFXIVModule(pid, client->processName, &modBaseAddr, &modBaseSize))
                {
                    if (modBaseSize != client->moduleSize)
                        continue;

                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
                    if (hProcess == NULL)
                    {
                        MESSAGEBOX_ASTERISK("관리자 권한으로 실행시켜주세요!");
                        return 1;
                    }

                    if (GetModuleFileNameEx(hProcess, NULL, filePath, sizeof(filePath) / sizeof(WCHAR)) == 0)
                    {
                        MESSAGEBOX_ASTERISK("관리자 권한으로 실행시켜주세요!");
                        return 1;
                    }

                    if (getFileSize(filePath) != client->exeSize)
                        continue;

                    patch = client->patches;
                    do
                    {
                        ReadProcessMemory(hProcess, modBaseAddr + patch->Offset, buff, strlen(patch->chkBytes), NULL);
                        if (memcmp(buff, patch->chkBytes, strlen(patch->chkBytes)) == 0)
                        {
                            res |= true;
                        }
                        else
                        {
                            if (memcmp(buff, patch->oldBytes, strlen(patch->oldBytes)) == 0)
                            {
                                WriteProcessMemory(hProcess, modBaseAddr + patch->Offset, patch->newBytes, strlen(patch->newBytes), NULL);
                                res |= true;
                            }
                        }

                        patch++;
                    }
                    while (patch->Offset != 0);

                    CloseHandle(hProcess);
                }
            }
        }
    }

    CloseHandle(snapshot);

    if (res)
        MESSAGEBOX_INFOMATION("성공적으로 적용했습니다!");
    else
        MESSAGEBOX_INFOMATION("파이널 판타지 14 가 실행중이 아니거나, 지원되지 않는 버전입니다.\n\n지원되는 클라이언트 버전 : " FFXIV_VERSION);

    return 0;
}

RELEASE_RESULT checkLatestRelease(LPWSTR lpUrl, DWORD cbUrl)
{
#define HOST    L"api.github.com"
#define PATH    L"/repos/RyuaNerin/FIME/releases/latest"

    RELEASE_RESULT result = NETWORK_ERROR;

    BOOL      bResults = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    std::string response;
    DWORD dwSize;
    DWORD dwRead;

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
    {
        size_t dwOffset;
        do
        {
            dwSize = 0;
            bResults = WinHttpQueryDataAvailable(hRequest, &dwSize);
            if (!bResults || dwSize == 0)
                break;

            while (dwSize > 0)
            {
                dwOffset = response.size();
                response.resize(dwOffset + dwSize);

                bResults = WinHttpReadData(hRequest, &response[dwOffset], dwSize, &dwRead);
                if (!bResults)
                {
                    dwRead = 0;
                    break;
                }

                response.resize(dwOffset + dwRead);

                if (dwRead == 0)
                    break;

                dwSize -= dwRead;
            }
        } while (true);
    }
    if (bResults)
    {
        result = PARSING_ERROR;

        int length = MultiByteToWideChar(CP_UTF8, 0, response.c_str(), (int)response.size(), NULL, 0);
        std::unique_ptr<wchar_t[]> wbuf(new wchar_t[length + 1]);
        memset(wbuf.get(), 0, length * sizeof(wchar_t));
        MultiByteToWideChar(CP_UTF8, 0, response.c_str(), (int)response.size(), wbuf.get(), length);

        std::wstring str(wbuf.get());
        std::wsmatch match;

        std::wregex regex_tag(L"\"tag_name\"[ \\t]*:[ \\t]*\"([^\"]+)\"");
        if (std::regex_search(str, match, regex_tag))
        {
            if (match[1].compare(TEXT(VERSION_STR)) == 0)
            {
                result = LATEST;
            }
            else
            {
                std::wregex regex_url(L"\"html_url\"[ \\t]*:[ \\t]*\"([^\"]+)\"");
                if (std::regex_search(str, match, regex_url))
                {
                    result = NEW_RELEASE;

                    std::wstring url = match[1];
                    url.copy(lpUrl, min(url.length(), cbUrl), 0);
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

BOOL getFFXIVModule(DWORD pid, LPCWSTR lpModuleName, PBYTE* modBaseAddr, DWORD* modBaseSize)
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
                if (lstrcmp(snapEntry.szModule, lpModuleName) == 0)
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

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hWnd, message, wParam, lParam);
}
