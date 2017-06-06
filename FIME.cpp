#include <regex>
#include <memory>
#include <cmath>

#include <windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <winhttp.h>
#include <codecvt>

#include <json\json.h>

#include "resource.h"

#define FIME_BUFFERSIZE     2048

#define FIME_PROJECT_NAME   L"FIME v" TEXT(FIME_VERSION_STR)

#define FIME_DEFAULT_PATCH_JSON \
"{" \
"  \"version\": \"v3.4 (2017.05.23.0000.0000(2603565, ex1:2017.05.18.0000.0000)\"," \
"  \"x64\": [" \
"    {" \
"      \"patch\":     \"EB\"," \
"      \"signature\": \"741B488B86307100000FBED1488D8E30710000FF5058C686\"" \
"    }," \
"    {" \
"      \"patch\":     \"EB\"," \
"      \"signature\": \"7424488B4E08488B01FF50388B96800400004C8B00488BC8\"" \
"    }" \
"  ]," \
"  \"x32\": [" \
"    {" \
"      \"patch\": \"EB\"," \
"      \"signature\": \"741C8B93184200008B522C0FBEC0508D8B18420000FFD2C6\"" \
"    }," \
"    {" \
"      \"patch\": \"EB\"," \
"      \"signature\": \"74208B4E048B118B421CFFD08B8E9C0300008B108B520451\"" \
"    }" \
"  ]" \
"}" \


typedef struct _FIME_MEMORY
{
    BYTE*   patch;
    int     patchSize;
    BYTE*   signature;
    int     signatureSize;
} FIME_MEMORY;
typedef struct _FIME_PATCH
{
    std::wstring *version;
    int          x32Count;
    FIME_MEMORY* x32;
#if _WIN64
    int          x64Count;
    FIME_MEMORY* x64;
#endif
} FIME_PATCH;

FIME_PATCH PATCH;

enum RELEASE_RESULT : DWORD
{
    LATEST,
    NEW_RELEASE,
    NETWORK_ERROR,
    PARSING_ERROR
};
enum PATCH_RESULT : DWORD
{
    SUCCESS,
    NOT_SUPPORTED,
    REQUIRE_ADMIN
};

#ifndef _DEBUG
#define MESSAGEBOX_INFOMATION(MSG)  MessageBox(NULL, MSG, FIME_PROJECT_NAME, MB_OK | MB_ICONINFORMATION);
#define MESSAGEBOX_ASTERISK(MSG)    MessageBox(NULL, MSG, FIME_PROJECT_NAME, MB_OK | MB_ICONASTERISK);
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
		fmt_str._Copy_s(formatted.get(), n, fmt_str.size(), 0);
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

#ifndef _DEBUG
RELEASE_RESULT checkLatestRelease();
#endif

bool getFFXIVModule(DWORD pid, LPCWSTR lpModuleName, PBYTE* modBaseAddr, DWORD* modBaseSize);
bool setPrivilege();
void getPatches(FIME_MEMORY** memory, int* memoryCount, Json::Value &patches);
void getMemoryPatches();
PATCH_RESULT ffxivPatch(PROCESSENTRY32 pEntry, FIME_MEMORY* patch, int8_t patchCount);

#ifdef _DEBUG
int wmain(int argc, wchar_t **argv, wchar_t **env)
#else
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int cmdShow)
#endif
{
#ifndef _DEBUG
    switch (checkLatestRelease())
    {
        case NEW_RELEASE:
            MESSAGEBOX_INFOMATION(L"최신 버전이 릴리즈 되었습니다!");
            ShellExecute(NULL, NULL, L"\"https://github.com/RyuaNerin/FIME/releases/latest\"", NULL, NULL, SW_SHOWNORMAL);
            return 1;

        case NETWORK_ERROR:
            if (MessageBox(NULL, L"최신 릴리즈 정보를 가져오지 못하였습니다.\n계속 실행하시겠습니까?", FIME_PROJECT_NAME, MB_YESNO | MB_ICONQUESTION) == IDNO)
                return -1;

        case PARSING_ERROR:
            MESSAGEBOX_ASTERISK(L"최신 릴리즈 정보를 가져오는 중 오류가 발생하였습니다.");
            return -1;
    }
#endif

    DEBUGLOG("ThreadPrivilege");
    if (!setPrivilege())
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

    PATCH_RESULT res;

    int          patchCount;
    FIME_MEMORY* patch;

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
                res = ffxivPatch(entry, patch, patchCount);
                switch (res)
                {
                    case NOT_SUPPORTED:
                    {
                        std::wstring message = L"지원되지 않는 파이널 판타지 14 버전입니다.\n\n지원되는 클라이언트 버전 : " + *PATCH.version;
                        MESSAGEBOX_ASTERISK(message.c_str())
                        return 1;
                    }

                    case REQUIRE_ADMIN:
                        MESSAGEBOX_ASTERISK( L"관리자 권한으로 실행시켜주세요!")
                        return 1;
                }
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);

    MESSAGEBOX_INFOMATION(L"성공적으로 적용했습니다!")
    
#ifdef _DEBUG
    std::string temp;
    std::cin >> temp;
#endif

    return 0;
}

PATCH_RESULT ffxivPatch(HANDLE hProcess, PBYTE modBaseAddr, DWORD modBaseSize, FIME_MEMORY patch);
PATCH_RESULT ffxivPatch(PROCESSENTRY32 pEntry, FIME_MEMORY* patch, int8_t patchCount)
{
    PBYTE modBaseAddr;
    DWORD modBaseSize;

    if (!getFFXIVModule(pEntry.th32ProcessID, pEntry.szExeFile, &modBaseAddr, &modBaseSize))
        return REQUIRE_ADMIN;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pEntry.th32ProcessID);
    if (hProcess == NULL)
        return REQUIRE_ADMIN;

    PATCH_RESULT result;
    for (int8_t i = 0; i < patchCount; ++i)
    {
        result = ffxivPatch(hProcess, modBaseAddr, modBaseSize, patch[i]);
        if (result != SUCCESS)
            return result;
    }

    return SUCCESS;
}

int findArray(BYTE* source, int sourceSize, BYTE* pattern, int patternSize, int* nextPos);
PATCH_RESULT ffxivPatch(HANDLE hProcess, PBYTE modBaseAddr, DWORD modBaseSize, FIME_MEMORY patch)
{
    bool res = false;

    PBYTE modBaseLimit = modBaseAddr + modBaseSize - patch.signatureSize;

    BYTE buff[FIME_BUFFERSIZE];
    SIZE_T read;
    int nextPos;

    SIZE_T toRead;
    int pos;

    modBaseSize += patch.patchSize;
    while (modBaseAddr < modBaseLimit)
    {
        toRead = (SIZE_T)(modBaseLimit - modBaseAddr);
        if (toRead > sizeof(buff))
            toRead = sizeof(buff);

        if (toRead < patch.signatureSize)
            break;

        if (!ReadProcessMemory(hProcess, modBaseAddr, buff, toRead, &read))
            return REQUIRE_ADMIN;

        pos = findArray(buff, (int)read, patch.signature + patch.patchSize, patch.signatureSize - patch.patchSize, &nextPos);
        if (pos != -1)
        {
            memset(buff, 0, patch.patchSize);

            if (ReadProcessMemory(hProcess, modBaseAddr + pos - patch.patchSize, buff, patch.patchSize, &read) &&
                read == patch.patchSize &&
                memcmp(buff, patch.patch, patch.patchSize) == 0)
                res = true;

            else
            {
                PBYTE addr = modBaseAddr + pos - patch.patchSize;
                SIZE_T written;

                if (WriteProcessMemory(hProcess, addr, patch.patch, patch.patchSize, &written) && written == patch.patchSize)
                    res = true;
            }

            modBaseAddr += pos + patch.signatureSize;
        }
        else
        {
            modBaseAddr += read - patch.signatureSize + 1;
        }
    }

    if (res)
        return SUCCESS;
    else
        return NOT_SUPPORTED;
}

void computeKMS(const BYTE* pattern, int patternSize, int* lps);
int findArray(BYTE* source, int sourceSize, BYTE* pattern, int patternSize, int* nextPos)
{
    int lps[FIME_BUFFERSIZE];
    computeKMS(pattern, patternSize, lps);

    int i = 0;
    int j = 0;
    while (i < sourceSize)
    {
        if (source[i] == pattern[j])
        {
            j++;
            i++;
        }

        if (j == patternSize)
            return i - j;

        if (i < sourceSize && source[i] != pattern[j])
        {
            if (j != 0)
                j = lps[j - 1];
            else
                i = i + 1;
        }
    }
    
    return -1;
}
void computeKMS(const BYTE* pattern, int patternSize, int* lps)
{
    int len = 0;
    lps[0] = 0;

    int i = 1;
    while (i < patternSize)
    {
        if (pattern[i] == pattern[len])
        {
            len++;
            lps[i] = len;
            i++;
        }
        else if (len != 0)
        {
            len = lps[len-1];
        }
        else
        {
            lps[i] = 0;
            i++;
        }
    }
}

bool setPrivilege()
{
    bool res = false;

    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) == TRUE)
    {
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid) == TRUE)
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

bool getHttp(LPCWSTR host, LPCWSTR path, std::string &body)
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

    hSession = WinHttpOpen(FIME_PROJECT_NAME, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession)
        bResults = WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);
    if (bResults)
        hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
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
				if (!bResults || dwRead == 0)
					break;

                body.resize(dwOffset + dwRead);

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

#ifndef _DEBUG
RELEASE_RESULT checkLatestRelease()
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
            if (tag_name.compare(FIME_VERSION_STR) == 0)
            {
                result = LATEST;
            }
            else
            {
                result = NEW_RELEASE;
            }
        }
    }

    return result;
}
#endif

void getMemoryPatches()
{
    std::string body;
//#ifndef _DEBUG
    if (!getHttp(L"raw.githubusercontent.com", L"/RyuaNerin/FIME/master/patch.json", body))
//#endif
        body.append(FIME_DEFAULT_PATCH_JSON);
    
    Json::Reader jsonReader;
    Json::Value json;
    if (!jsonReader.parse(body, json))
    {
        body.clear();
        body.append(FIME_DEFAULT_PATCH_JSON);

        jsonReader.parse(body, json);
    }

    std::string version = json["version"].asString();

    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> c2wc;
    PATCH.version = new std::wstring(c2wc.from_bytes(version));
    
    getPatches(&PATCH.x32, &PATCH.x32Count, json["x32"]);

#ifdef _WIN64
    getPatches(&PATCH.x64, &PATCH.x64Count, json["x64"]);
#endif
}

void hexToString(Json::Value value, BYTE** bytes, int *length);
void getPatches(FIME_MEMORY** memory, int* memoryCount, Json::Value &patches)
{
    Json::Value patch;

    *memoryCount = patches.size();
    *memory      = new FIME_MEMORY[*memoryCount];

    unsigned int index;
    for (index = 0; index < patches.size(); ++index)
    {
        patch = patches[index];
        hexToString(patch["signature"], &((*memory)[index].signature), &((*memory)[index].signatureSize));
        hexToString(patch["patch"],     &((*memory)[index].patch),     &((*memory)[index].patchSize));
    }
}

BYTE hex2dec(const char *hex);
void hexToString(Json::Value value, BYTE** bytes, int *length)
{
    std::string  str = value.asCString();
    const char* cstr = str.c_str();

    *length = (int)(str.length() / 2);
    BYTE* arr = new BYTE[*length];

    for (int i = 0; i < *length; ++i)
        arr[i] = hex2dec(cstr + i * 2);

    *bytes = arr;
}

BYTE hex2dec(const char *hex)
{
    BYTE val = 0;

         if (hex[0] >= '0' && hex[0] <= '9') val = (hex[0] - '0') << 4;
    else if (hex[0] >= 'a' && hex[0] <= 'f') val = (hex[0] - 'a' + 10) << 4;
    else if (hex[0] >= 'A' && hex[0] <= 'F') val = (hex[0] - 'A' + 10) << 4;
    
         if (hex[1] >= '0' && hex[1] <= '9') val |= hex[1] - '0';
    else if (hex[1] >= 'a' && hex[1] <= 'f') val |= hex[1] - 'a' + 10;
    else if (hex[1] >= 'A' && hex[1] <= 'F') val |= hex[1] - 'A' + 10;

    return val;
}

bool getFFXIVModule(DWORD pid, LPCWSTR lpModuleName, PBYTE* modBaseAddr, DWORD* modBaseSize)
{
    bool res = false;

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
                    res = true;
                    break;
                }
            } while (Module32Next(hSnapshot, & snapEntry));
        }
        CloseHandle(hSnapshot);
    }

    return res;
}

#ifndef _DEBUG
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hWnd, message, wParam, lParam);
}
#endif
