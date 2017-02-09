#include <regex>
#include <memory>

#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <winhttp.h>

#include <json\json.h>

#include "resource.h"

#define PROJECT_NAME            L"FIME v" TEXT(VERSION_STR)

#define DEFAULT_PATCH_JSON \
"{" \
"  \"version\": \"v3.21, 2016.12.26.0000.0000(2245781, ex1:2016.12.26.0000.0000)\"," \
"  \"x64\": {" \
"    \"exeSize\": 24430672," \
"    \"moduleSize\": 28008448," \
"    \"patches\": [" \
"      {" \
"        \"offset\": 2561585," \
"        \"newLength\": 1," \
"        \"new\": \"EB1B488B86903100000FBED1488D8E90310000FF5058C686\"," \
"        \"old\": \"741B488B86903100000FBED1488D8E90310000FF5058C686\"" \
"      }," \
"      {" \
"        \"offset\": 9251362," \
"        \"newLength\": 1," \
"        \"new\": \"EB24488B4E08488B01FF50388B96800400004C8B00488BC8\"," \
"        \"old\": \"7424488B4E08488B01FF50388B96800400004C8B00488BC8\"" \
"      }" \
"    ]" \
"  }," \
"  \"x32\": {" \
"    \"exeSize\": 17311824," \
"    \"moduleSize\": 20234240," \
"    \"patches\": [" \
"      {" \
"        \"offset\": 2049539," \
"        \"newLength\": 1," \
"        \"new\": \"EB1C8B935C2200008B522C0FBEC0508D8B5C220000FFD2C6\"," \
"        \"old\": \"741C8B935C2200008B522C0FBEC0508D8B5C220000FFD2C6\"" \
"      }," \
"      {" \
"        \"offset\": 7449555," \
"        \"newLength\": 1," \
"        \"new\": \"EB208B4E048B118B421CFFD08B8E9C0300008B108B520451\"," \
"        \"old\": \"74208B4E048B118B421CFFD08B8E9C0300008B108B520451\"" \
"      }" \
"    ]" \
"  }" \
"}"

typedef struct _FIME_MEMORY
{
    size_t  offset;
    size_t  newLength;
    char*   newArr;
    size_t  newArrLength;
    char*   oldArr;
    size_t  oldArrLength;
} FIME_MEMORY;
typedef struct _FIME_CLIENT
{
    size_t  exeSize;
    size_t  moduleSize;
    size_t  patchesCount;
    FIME_MEMORY* patches;
} FIME_CLIENT;
typedef struct _FIME_PATCH
{
    std::wstring version;
    FIME_CLIENT x32;
#if _WIN64
    FIME_CLIENT x64;
#endif
} FIME_PATCH;

FIME_PATCH PATCH;

enum FIME_RESULT : DWORD
{
    NOT_FOUND,
    SUCCESS,
    NOT_SUPPORTED
};

enum RELEASE_RESULT : DWORD
{
    LATEST,
    NEW_RELEASE,
    NETWORK_ERROR,
    PARSING_ERROR
};

#ifndef _DEBUG
#define MESSAGEBOX_INFOMATION(MSG)  MessageBox(NULL, MSG, PROJECT_NAME, MB_OK | MB_ICONINFORMATION)
#define MESSAGEBOX_ASTERISK(MSG)    MessageBox(NULL, MSG, PROJECT_NAME, MB_OK | MB_ICONASTERISK)
#define DEBUGLOG
#else
#include <iostream>
#define MESSAGEBOX_INFOMATION(MSG)  { std::wcout << MSG << std::endl; }
#define MESSAGEBOX_ASTERISK(MSG)    { std::wcout << MSG << std::endl; }
void DEBUGLOG(const std::string fmt_str, ...)
{
    int final_n;
    int n = ((int)fmt_str.size()) * 2;
    std::unique_ptr<char[]> formatted;
    va_list va;
    while (1)
    {
        formatted.reset(new char[n]);
        std::strcpy(&formatted[0], fmt_str.c_str());
        va_start(va, fmt_str);
        final_n = vsnprintf_s(&formatted[0], n, n - 1, fmt_str.c_str(), va);
        va_end(va);
        if (final_n < 0 || final_n >= n)
            n += std::abs(final_n - n + 1);
        else
            break;
    }

    std::cout << std::string(formatted.get()) << std::endl;
}
void DEBUGLOG(const std::wstring fmt_str, ...)
{
    int final_n;
    int n = ((int)fmt_str.size()) * 2;
    std::unique_ptr<wchar_t[]> formatted;
    va_list va;
    while (1)
    {
        formatted.reset(new wchar_t[n]);
        std::wcsstr(&formatted[0], fmt_str.c_str());
        va_start(va, fmt_str);
        final_n = _vsnwprintf_s(&formatted[0], n, n - 1, fmt_str.c_str(), va);
        va_end(va);
        if (final_n < 0 || final_n >= n)
            n += std::abs(final_n - n + 1);
        else
            break;
    }

    std::wcout << std::wstring(formatted.get()) << std::endl;
}
#endif

RELEASE_RESULT checkLatestRelease(LPWSTR lpUrl, size_t cbUrl);
BOOL getFFXIVModule(DWORD pid, LPCWSTR lpModuleName, PBYTE* modBaseAddr, DWORD* modBaseSize);
DWORD getFileSize(LPCWSTR path);
bool SetPrivilege();
void getPatches(FIME_CLIENT *client, Json::Value &arc);
void getMemoryPatches();

#ifdef _DEBUG
int wmain(int argc, wchar_t **argv, wchar_t **env)
#else
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int cmdShow)
#endif
{
    WCHAR filePath[4096];

#ifndef _DEBUG
    switch (checkLatestRelease(filePath, sizeof(filePath)))
    {
        case LATEST:
            break;

        case NEW_RELEASE:
            MESSAGEBOX_INFOMATION(L"최신 버전이 릴리즈 되었습니다!");
            ShellExecute(NULL, NULL, filePath, NULL, NULL, SW_SHOWNORMAL);
            return 1;

        case NETWORK_ERROR:
            if (MessageBox(NULL, L"최신 릴리즈 정보를 가져오지 못하였습니다.\n계속 실행하시겠습니까?", PROJECT_NAME, MB_YESNO | MB_ICONQUESTION) == IDNO)
                return -1;

        case PARSING_ERROR:
            MESSAGEBOX_ASTERISK(L"최신 릴리즈 정보를 가져오는 중 오류가 발생하였습니다.");
            return -1;
    }
#endif

    DEBUGLOG("ThreadPrivilege");
    if (!SetPrivilege())
    {
        MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
        return 1;
    }

    PROCESSENTRY32 entry = { 0, };
    entry.dwSize = sizeof(PROCESSENTRY32);

    DEBUGLOG("CreateToolhelp32Snapshot");
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
        return 1;
    }

    getMemoryPatches();

    FIME_RESULT res = NOT_FOUND;

    const FIME_CLIENT* client;

    DWORD pid;
    HANDLE hProcess;
    DWORD oldProtect;

    PBYTE modBaseAddr;
    DWORD modBaseSize;

    BYTE buff[256];

    void* offset;
    size_t i;

    DEBUGLOG("Process32First");
    if (Process32First(snapshot, &entry))
    {
        do
        {
            client = nullptr;

            DEBUGLOG("ProcessName : [%4X] %S", entry.th32ProcessID, entry.szExeFile);
#if _WIN64
            if (lstrcmpi(entry.szExeFile, L"ffxiv_dx11.exe") == 0 ||
                lstrcmpi(entry.szExeFile, L"ffxiv_dx11_multi.exe") == 0)
                client = &PATCH.x64;
            else
#endif
            if (lstrcmpi(entry.szExeFile, L"ffxiv.exe") == 0 ||
                lstrcmpi(entry.szExeFile, L"ffxiv_multi.exe") == 0)
                client = &PATCH.x32;

            if (client != nullptr)
            {
                pid = entry.th32ProcessID;

                if (getFFXIVModule(pid, entry.szExeFile, &modBaseAddr, &modBaseSize))
                {
                    if (modBaseSize != client->moduleSize)
                        continue;

                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
                    if (hProcess == NULL)
                    {
                        MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
                        return 1;
                    }

                    if (GetModuleFileNameEx(hProcess, NULL, filePath, sizeof(filePath) / sizeof(WCHAR)) == 0)
                    {
                        MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
                        return 1;
                    }

                    if (getFileSize(filePath) != client->exeSize)
                        continue;

                    for (i = 0; i < client->patchesCount; ++i)
                    {
                        offset = modBaseAddr + client->patches[i].offset;
                        ReadProcessMemory(hProcess, offset, buff, client->patches[i].newArrLength, NULL);
                        if (std::memcmp(client->patches[i].newArr, buff, client->patches[i].newArrLength) == 0)
                        {
                            res = SUCCESS;
                        }
                        else
                        {
                            if (std::memcmp(client->patches[i].oldArr, buff, client->patches[i].oldArrLength) == 0)
                            {
                                if (VirtualProtectEx(hProcess, offset, client->patches[i].newLength, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE)
                                {
                                    MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
                                    return 1;
                                }

                                WriteProcessMemory(hProcess, offset, client->patches[i].newArr, client->patches[i].newLength, NULL);
                                VirtualProtectEx(hProcess, offset, client->patches[i].newLength, oldProtect, &oldProtect);

                                res = SUCCESS;
                            }
                            else
                            {
                                if (res == NOT_FOUND)
                                    res = NOT_SUPPORTED;
                            }
                        }
                    }

                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);

    switch (res)
    {
        case SUCCESS:       MESSAGEBOX_INFOMATION(L"성공적으로 적용했습니다!"); break;
        case NOT_FOUND:     MESSAGEBOX_ASTERISK(L"파이널 판타지 14 가 실행중이 아닙니다."); break;
        case NOT_SUPPORTED:
        {
            std::wstring message = L"지원되지 않는 파이널 판타지 14 버전입니다.\n\n지원되는 클라이언트 버전 : " + PATCH.version;
            MESSAGEBOX_ASTERISK(message.c_str());
            break;
        }
    }
    
#ifdef _DEBUG
    std::string temp;
    std::cin >> temp;
#endif

    return 0;
}

bool SetPrivilege()
{
    bool res = false;

    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) == TRUE)
    {
        LUID luid;
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid) == TRUE)
        {
            TOKEN_PRIVILEGES priviliges = { 0, };

            priviliges.PrivilegeCount = 1;
            priviliges.Privileges[0].Luid = luid;
            priviliges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (AdjustTokenPrivileges(hToken, FALSE, &priviliges, sizeof(priviliges), NULL, NULL))
                res = true;
        }

        CloseHandle(hToken);
    }


    return res;
}

bool getHttp(std::wstring host, std::wstring path, std::string &body)
{
    bool res = false;

    RELEASE_RESULT result = NETWORK_ERROR;

    BOOL      bResults = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    DWORD dwStatusCode;
    DWORD dwSize;
    DWORD dwRead;

    hSession = WinHttpOpen(PROJECT_NAME, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession)
        bResults = WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);
    if (bResults)
        hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, NULL);
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (bResults)
    {
        dwSize = sizeof(dwStatusCode);
        bResults = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    }
    if (bResults)
        bResults = dwStatusCode == 200;
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
                dwOffset = body.size();
                body.resize(dwOffset + dwSize);

                bResults = WinHttpReadData(hRequest, &body[dwOffset], dwSize, &dwRead);
                if (!bResults)
                {
                    dwRead = 0;
                    break;
                }

                body.resize(dwOffset + dwRead);

                if (dwRead == 0)
                    break;

                dwSize -= dwRead;
            }
        } while (true);

        res = true;
    }
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return res;
}

RELEASE_RESULT checkLatestRelease(LPWSTR lpUrl, size_t cbUrl)
{
    RELEASE_RESULT result = NETWORK_ERROR;

    std::string body;
    if (getHttp(L"api.github.com", L"/repos/RyuaNerin/FIME/releases/latest", body))
    {
        result = PARSING_ERROR;

        Json::Reader jsonReader;
        Json::Value json;

        if (jsonReader.parse(body, json))
        {
            std::string tag_name = json["tag_name"].asString();
            if (tag_name.compare(VERSION_STR) == 0)
            {
                result = LATEST;
            }
            else
            {
                std::string html_url = json["html_url"].asString();

                int length = MultiByteToWideChar(CP_UTF8, 0, html_url.c_str(), (int)html_url.size(), NULL, 0);
                if (length > 0)
                {
                    std::unique_ptr<wchar_t[]> wbuf(new wchar_t[length + 1]());
                    MultiByteToWideChar(CP_UTF8, 0, html_url.c_str(), (int)html_url.size(), wbuf.get(), length);

                    memcpy_s(lpUrl, cbUrl, &wbuf[0], length);
                    result = NEW_RELEASE;
                }
            }
        }
    }

    return result;
}

void getPatches(Json::Value &arc);
void getMemoryPatches()
{
    std::string body;
    if (!getHttp(L"raw.githubusercontent.com", L"/RyuaNerin/FIME/master/patch.json", body))
        body.append(DEFAULT_PATCH_JSON);
    
    Json::Reader jsonReader;
    Json::Value json;
    if (jsonReader.parse(body, json))
    {
        body.clear();
        body.append(DEFAULT_PATCH_JSON);

        jsonReader.parse(body, json);
    }

    std::string version = json["version"].asString();
    PATCH.version.assign(version.begin(), version.end());

    getPatches(&PATCH.x32, json["x32"]);

#ifdef _WIN64
    getPatches(&PATCH.x64, json["x64"]);
#endif
}

void hexToString(Json::Value value, char** bytes, size_t *length);
void getPatches(FIME_CLIENT *client, Json::Value &arc)
{
    Json::Value patches = arc["patches"];
    Json::Value patch;

    client->exeSize      = (size_t)arc["exeSize"].asInt64();
    client->moduleSize   = (size_t)arc["moduleSize"].asInt64();
    client->patchesCount = patches.size();
    client->patches      = new FIME_MEMORY[client->patchesCount];

    unsigned int index;
    for (index = 0; index < patches.size(); ++index)
    {
        patch = patches[index];
        client->patches[index].offset    = (size_t)patch["offset"].asInt64();
        client->patches[index].newLength = (size_t)patch["newLength"].asInt64();

        hexToString(patch["old"], &client->patches[index].oldArr, &client->patches[index].oldArrLength);
        hexToString(patch["new"], &client->patches[index].newArr, &client->patches[index].newArrLength);
    }
}

char hex2dec(const char *hex);
void hexToString(Json::Value value, char** bytes, size_t *length)
{
    std::string  str = value.asCString();
    const char* cstr = str.c_str();

    *length = (size_t)(str.length() / 2);
    char* arr = new char[*length];

    for (SIZE_T i = 0; i < *length; ++i)
        arr[i] = hex2dec(cstr + i * 2);

    *bytes = arr;
}

char hex2dec(const char *hex)
{
    char val = 0;

         if (hex[0] >= '0' && hex[0] <= '9') val = (hex[0] - '0') << 4;
    else if (hex[0] >= 'a' && hex[0] <= 'f') val = (hex[0] - 'a' + 10) << 4;
    else if (hex[0] >= 'A' && hex[0] <= 'F') val = (hex[0] - 'A' + 10) << 4;
    
         if (hex[1] >= '0' && hex[1] <= '9') val |= hex[1] - '0';
    else if (hex[1] >= 'a' && hex[1] <= 'f') val |= hex[1] - 'a' + 10;
    else if (hex[1] >= 'A' && hex[1] <= 'F') val |= hex[1] - 'A' + 10;

    return val;
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
                if (lstrcmpi(snapEntry.szModule, lpModuleName) == 0)
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
