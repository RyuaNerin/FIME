#include <regex>
#include <memory>

#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <winhttp.h>
#include <codecvt>

#include <json\json.h>

#include "resource.h"

#define PROJECT_NAME            L"FIME v" TEXT(VERSION_STR)

#define DEFAULT_PATCH_JSON \
"{" \
"  \"version\": \"v3.3 (2017.02.24.0000.0000(2405653, ex1:2017.02.21.0000.0000)\"," \
"  \"x64\": [" \
"    {" \
"      \"offset\": 2597921," \
"      \"newLength\": 1," \
"      \"newBytes\": \"EB1B488B86903100000FBED1488D8E90310000FF5058C686\"," \
"      \"oldBytes\": \"741B488B86903100000FBED1488D8E90310000FF5058C686\"" \
"    }," \
"    {" \
"      \"offset\": 9524946," \
"      \"newLength\": 1," \
"      \"newBytes\": \"EB24488B4E08488B01FF50388B96800400004C8B00488BC8\"," \
"      \"oldBytes\": \"7424488B4E08488B01FF50388B96800400004C8B00488BC8\"" \
"    }" \
"  ]," \
"  \"x32\": [" \
"    {" \
"      \"offset\": 2049539," \
"      \"newLength\": 1," \
"      \"newBytes\": \"EB1C8B935C2200008B522C0FBEC0508D8B5C220000FFD2C6\"," \
"      \"oldBytes\": \"741C8B935C2200008B522C0FBEC0508D8B5C220000FFD2C6\"" \
"    }," \
"    {" \
"      \"offset\": 7449555," \
"      \"newLength\": 1," \
"      \"newBytes\": \"EB208B4E048B118B421CFFD08B8E9C0300008B108B520451\"," \
"      \"oldBytes\": \"74208B4E048B118B421CFFD08B8E9C0300008B108B520451\"" \
"    }" \
"  ]" \
"}" \


typedef struct _FIME_MEMORY
{
    size_t  offset;
    size_t  newLength;
    int8_t* newArr;
    size_t  newArrLength;
    int8_t* oldArr;
    size_t  oldArrLength;
} FIME_MEMORY;
typedef struct _FIME_PATCH
{
    std::wstring version;
    size_t       x32Count;
    FIME_MEMORY* x32;
#if _WIN64
    size_t       x64Count;
    FIME_MEMORY* x64;
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
BOOL getFFXIVModule(DWORD pid, LPCWSTR lpModuleName, PBYTE* modBaseAddr);
DWORD getFileSize(LPCWSTR path);
bool SetPrivilege();
void getPatches(FIME_MEMORY** memory, size_t* memoryCount, Json::Value &arc);
void getMemoryPatches();

#ifdef _DEBUG
int wmain(int argc, wchar_t **argv, wchar_t **env)
#else
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int cmdShow)
#endif
{
#ifndef _DEBUG
    WCHAR wBuffer[4096];
    switch (checkLatestRelease(wBuffer, sizeof(wBuffer)))
    {
        case LATEST:
            break;

        case NEW_RELEASE:
            MESSAGEBOX_INFOMATION(L"최신 버전이 릴리즈 되었습니다!");
            ShellExecute(NULL, NULL, wBuffer, NULL, NULL, SW_SHOWNORMAL);
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

    size_t       patchCount;
    FIME_MEMORY* patch;

    DWORD pid;
    HANDLE hProcess;
    DWORD oldProtect;

    PBYTE modBaseAddr;

    int8_t buff[256];

    void* offset;
    size_t i;

    DEBUGLOG("Process32First");
    if (Process32First(snapshot, &entry))
    {
        do
        {
            patch = nullptr;

            DEBUGLOG("ProcessName : [%4X] %S", entry.th32ProcessID, entry.szExeFile);
#if _WIN64
            if (lstrcmpi(entry.szExeFile, L"ffxiv_dx11.exe") == 0 ||
                lstrcmpi(entry.szExeFile, L"ffxiv_dx11_multi.exe") == 0)
            {
                patch = PATCH.x64;
                patchCount = PATCH.x64Count;
            }
            else
#endif
            if (lstrcmpi(entry.szExeFile, L"ffxiv.exe") == 0 ||
                lstrcmpi(entry.szExeFile, L"ffxiv_multi.exe") == 0)
            {
                patch = PATCH.x32;
                patchCount = PATCH.x32Count;
            }

            if (patch != nullptr)
            {
                pid = entry.th32ProcessID;

                if (getFFXIVModule(pid, entry.szExeFile, &modBaseAddr))
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
                    if (hProcess == NULL)
                    {
                        MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
                        return 1;
                    }

                    for (i = 0; i < patchCount; ++i)
                    {
                        offset = modBaseAddr + patch[i].offset;
                        ReadProcessMemory(hProcess, offset, buff, patch[i].newArrLength, NULL);
                        if (std::memcmp(patch[i].newArr, buff, patch[i].newArrLength) == 0)
                        {
                            res = SUCCESS;
                        }
                        else
                        {
                            if (std::memcmp(patch[i].oldArr, buff, patch[i].oldArrLength) == 0)
                            {
                                if (VirtualProtectEx(hProcess, offset, patch[i].newLength, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE)
                                {
                                    MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
                                    return 1;
                                }

                                WriteProcessMemory(hProcess, offset, patch[i].newArr, patch[i].newLength, NULL);
                                VirtualProtectEx(hProcess, offset, patch[i].newLength, oldProtect, &oldProtect);

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

void getMemoryPatches()
{
    std::string body;
#ifdef DEBUG
    if (!getHttp(L"raw.githubusercontent.com", L"/RyuaNerin/FIME/master/patch.json", body))
#endif
        body.append(DEFAULT_PATCH_JSON);
    
    Json::Reader jsonReader;
    Json::Value json;
    if (!jsonReader.parse(body, json))
    {
        body.clear();
        body.append(DEFAULT_PATCH_JSON);

        jsonReader.parse(body, json);
    }

    std::string version = json["version"].asString();

    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> c2wc;
    PATCH.version = c2wc.from_bytes(version);
    
    getPatches(&PATCH.x32, &PATCH.x32Count, json["x32"]);

#ifdef _WIN64
    getPatches(&PATCH.x64, &PATCH.x64Count, json["x64"]);
#endif
}

void hexToString(Json::Value value, int8_t** bytes, size_t *length);
void getPatches(FIME_MEMORY** memory, size_t* memoryCount, Json::Value &patches)
{
    Json::Value patch;

    *memoryCount = patches.size();
    *memory      = new FIME_MEMORY[*memoryCount];

    unsigned int index;
    for (index = 0; index < patches.size(); ++index)
    {
        patch = patches[index];
        (*memory)[index].offset    = (size_t)patch["offset"].asInt64();
        (*memory)[index].newLength = (size_t)patch["newLength"].asInt64();

        hexToString(patch["oldBytes"], &((*memory)[index].oldArr), &((*memory)[index].oldArrLength));
        hexToString(patch["newBytes"], &((*memory)[index].newArr), &((*memory)[index].newArrLength));
    }
}

int8_t hex2dec(const char *hex);
void hexToString(Json::Value value, int8_t** bytes, size_t *length)
{
    std::string  str = value.asCString();
    const char* cstr = str.c_str();

    *length = (size_t)(str.length() / 2);
    int8_t* arr = new int8_t[*length];

    for (SIZE_T i = 0; i < *length; ++i)
        arr[i] = hex2dec(cstr + i * 2);

    *bytes = arr;
}

int8_t hex2dec(const char *hex)
{
    int8_t val = 0;

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

BOOL getFFXIVModule(DWORD pid, LPCWSTR lpModuleName, PBYTE* modBaseAddr)
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
