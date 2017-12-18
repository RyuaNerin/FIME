#include "stdafx.h"

#include "patch.h"

#include <codecvt>

#include "common.h"
#include "http.h"

void hexToString(Json::Value value, BYTE** bytes, int *length);
BYTE hex2dec(const char *hex);

FIME_PATCH getMemoryPatches()
{
    std::string body;
#ifndef _DEBUG
    if (!getHttp(L"raw.githubusercontent.com", L"/RyuaNerin/FIME/master/patch.json", body))
#endif
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

    FIME_PATCH patch;
    patch.version = new std::wstring(c2wc.from_bytes(version));

    getPatches(&patch.x32, &patch.x32Count, json["x32"]);
    getPatches(&patch.x64, &patch.x64Count, json["x64"]);

    return patch;
}

void getPatches(FIME_MEMORY** memory, int* memoryCount, Json::Value &patches)
{
    Json::Value patch;

    *memoryCount = patches.size();
    *memory = new FIME_MEMORY[*memoryCount];

    unsigned int index;
    for (index = 0; index < patches.size(); ++index)
    {
        patch = patches[index];
        hexToString(patch["signature"], &((*memory)[index].signature), &((*memory)[index].signatureSize));
        hexToString(patch["patch"], &((*memory)[index].patch), &((*memory)[index].patchSize));
    }
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
            } while (Module32Next(hSnapshot, &snapEntry));
        }
        CloseHandle(hSnapshot);
    }

    return res;
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
            len = lps[len - 1];
        }
        else
        {
            lps[i] = 0;
            i++;
        }
    }
}

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
