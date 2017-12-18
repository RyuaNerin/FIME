#pragma once

#include <string>

#include <Windows.h>
#include <tlhelp32.h>

#include <json/json.h>

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
    int          x64Count;
    FIME_MEMORY* x64;
} FIME_PATCH;

enum PATCH_RESULT : DWORD
{
    SUCCESS,
    NOT_SUPPORTED,
    REQUIRE_ADMIN
};

FIME_PATCH getMemoryPatches();
void getPatches(FIME_MEMORY** memory, int* memoryCount, Json::Value &patches);
PATCH_RESULT ffxivPatch(PROCESSENTRY32 pEntry, FIME_MEMORY* patch, int8_t patchCount);
