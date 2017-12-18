#include "stdafx.h"

#include <iostream>

#include <windows.h>
#include <TlHelp32.h>

#include "resource.h"
#include "checkLatestRelease.h"
#include "http.h"
#include "DebugLog.h"
#include "patch.h"
#include "common.h"

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

#ifdef _DEBUG
int wmain(int argc, wchar_t **argv, wchar_t **env)
{
    bool noMessageBox = false;
#else
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int cmdShow)
{
    bool noMessageBox = !std::wcsstr(lpCmdLine, L"/q");
#endif

#ifndef _DEBUG
#define MESSAGEBOX_INFOMATION(MSG)  if (noMessageBox) MessageBox(NULL, MSG, FIME_PROJECT_NAME, MB_OK | MB_ICONINFORMATION);
#define MESSAGEBOX_ASTERISK(MSG)    if (noMessageBox) MessageBox(NULL, MSG, FIME_PROJECT_NAME, MB_OK | MB_ICONASTERISK);
#else
#include <iostream>
#define MESSAGEBOX_INFOMATION(MSG)  { std::wcout << MSG << std::endl; }
#define MESSAGEBOX_ASTERISK(MSG)    { std::wcout << MSG << std::endl; }
#endif

#ifndef _DEBUG
    switch (checkLatestRelease())
    {
        case NEW_RELEASE:
            MESSAGEBOX_INFOMATION(L"최신 버전이 릴리즈 되었습니다!");
            if (noMessageBox)
                ShellExecute(NULL, NULL, L"\"https://github.com/RyuaNerin/FIME/releases/latest\"", NULL, NULL, SW_SHOWNORMAL);
            return 1;

        case NETWORK_ERROR:
            if (noMessageBox ||
                MessageBox(NULL, L"최신 릴리즈 정보를 가져오지 못하였습니다.\n계속 실행하시겠습니까?", FIME_PROJECT_NAME, MB_YESNO | MB_ICONQUESTION) == IDNO)
                return -1;

        case PARSING_ERROR:
            MESSAGEBOX_ASTERISK(L"최신 릴리즈 정보를 가져오는 중 오류가 발생하였습니다.");
            return -1;
    }
#endif

    DebugLog("ThreadPrivilege");
    if (!setPrivilege())
    {
        MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
        return 1;
    }

    PROCESSENTRY32 entry = { 0, };
    entry.dwSize = sizeof(PROCESSENTRY32);

    DebugLog("CreateToolhelp32Snapshot");
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        MESSAGEBOX_ASTERISK(L"관리자 권한으로 실행시켜주세요!");
        return 1;
    }

    FIME_PATCH PATCH = getMemoryPatches();

    int          patchCount;
    FIME_MEMORY* patch;

    PATCH_RESULT res;

    DebugLog("Process32First");
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            patch = nullptr;

            DebugLog("ProcessName : [%4X] %S", entry.th32ProcessID, entry.szExeFile);
            if (lstrcmpiW(entry.szExeFile, L"ffxiv_dx11.exe") == 0)
            {
                patch = PATCH.x64;
                patchCount = PATCH.x64Count;
            }
            else
            if (lstrcmpiW(entry.szExeFile, L"ffxiv.exe") == 0)
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
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    MESSAGEBOX_INFOMATION(L"성공적으로 적용했습니다!")
    
#ifdef _DEBUG
    std::string temp;
    std::cin >> temp;
#endif

    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hWnd, message, wParam, lParam);
}
