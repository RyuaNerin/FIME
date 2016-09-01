//#define __TEST

#include <stdio.h>
#include <windows.h>

#include "minhook/include/MinHook.h"

#pragma comment(lib, "Imm32.lib")

#ifdef __TEST
#include <windows.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef _UNICODE
#include <wchar.h>
#else
#include <stdio.h>
#endif

void DebugLog(const TCHAR *fmt, ...)
{
#ifdef _UNICODE
#define lvsnprintf  vswprintf
#else
#define lvsnprintf  vsnprintf
#endif

    va_list	va;
    TCHAR *str;
    int len;

    va_start(va, fmt);

    len = lstrlen(TEXT("FIME: ")) + lvsnprintf(NULL, 0, fmt, va) + 2;
    str = calloc(len, sizeof(TCHAR));
    if (str == NULL)
    {
        va_end(va);
        return;
    }

    len = wsprintf(str, TEXT("FIME: "));
    wvsprintf(str + len, fmt, va);

    va_end(va);

    OutputDebugString(str);

    free(str);
}
#else
#define DebugLog
#endif

typedef BOOL(WINAPI *D_ImmSetConversionStatus)(HIMC hIMC, DWORD fdwConversion, DWORD fdwSentence);
typedef HIMC(WINAPI *D_ImmAssociateContext)   (HWND hWnd, HIMC hIMC);
typedef BOOL(WINAPI *D_ImmGetOpenStatus)      (HIMC hIMC);

D_ImmSetConversionStatus __ImmSetConversionStatus;
D_ImmAssociateContext    __ImmAssociateContext;
D_ImmGetOpenStatus       __ImmGetOpenStatus;

typedef enum __IME_STATUS
{
    IMES_None,
    IMES_To_IME,
    IMES_IME
} IMES;

IMES  g_ime_status      = IMES_None;
DWORD g_last_conversion = 0;
DWORD g_last_sentence   = 0;

BOOL WINAPI _ImmSetConversionStatus(HIMC hIMC, DWORD fdwConversion, DWORD fdwSentence)
{
    DebugLog(TEXT("=============================="));
    DebugLog(TEXT("is_use_ime : %d"), g_ime_status);
    DebugLog(TEXT("-------------------"));
    DebugLog(TEXT("ImmSetConversionStatus"));
    DebugLog(TEXT("      hIMC : %016X"), hIMC);
    DebugLog(TEXT("conversion : %d"), fdwConversion);
    DebugLog(TEXT("  sentence : %d"), fdwSentence);

    if (g_ime_status == IMES_IME)
    {
        g_last_conversion = fdwConversion;
        g_last_sentence = fdwSentence;
    }
    else if (g_ime_status == IMES_To_IME)
    {
        g_ime_status = IMES_IME;

        fdwConversion = g_last_conversion;
        fdwSentence   = g_last_sentence;

        DebugLog(TEXT("---------------"));
        DebugLog(TEXT("conversion : %d"), fdwConversion);
        DebugLog(TEXT("  sentence : %d"), fdwSentence);
    }

    DebugLog(TEXT("Call original api"));
    return __ImmSetConversionStatus(hIMC, fdwConversion, fdwSentence);
}

HIMC WINAPI _ImmAssociateContext(HWND hWnd, HIMC hIMC)
{
    HIMC result;

    DebugLog(TEXT("=============================="));
    DebugLog(TEXT("is_use_ime : %d"), g_ime_status);
    DebugLog(TEXT("-------------------"));
    DebugLog(TEXT("ImmAssociateContext"));
    DebugLog(TEXT("           hWnd : %016X"), hWnd);
    DebugLog(TEXT("           hIMC : %016X"), hIMC);
    DebugLog(TEXT("           -----------"));
    DebugLog(TEXT("last_conversion : %d"), g_last_conversion);
    DebugLog(TEXT("  last_sentence : %d"), g_last_sentence);

    DebugLog(TEXT("Call original api"));
    result = __ImmAssociateContext(hWnd, hIMC);

    // Restore last conversation status.
    if (hIMC == NULL)
        g_ime_status = IMES_None;

    else if (g_ime_status == IMES_None)
        g_ime_status = IMES_To_IME;

    return result;
}

BOOL WINAPI _ImmGetOpenStatus(HIMC hIMC)
{
    return FALSE;
}

/*
TCHAR g_oldTitle[MAX_PATH] = TEXT("FINAL FANTASY XIV");
HANDLE g_hFFXIV = NULL;
*/

BOOL g_hooked = FALSE;
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    /*
    BOOL findFFXIVWindow = FALSE;
    HANDLE hFFXIV = NULL;
    TCHAR oldTitle[MAX_PATH];
    TCHAR newTitle[MAX_PATH];
    DWORD pidOfCurrentProcess;
    DWORD pidOfWindow;
    */

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DebugLog(TEXT("DLL_PROCESS_ATTACH"));

            if (MH_Initialize() == MH_OK)
            {
                g_hooked = TRUE;

                DebugLog(TEXT("Initialized"));
                MH_CreateHook(&ImmSetConversionStatus, &_ImmSetConversionStatus, (LPVOID*)&__ImmSetConversionStatus);
                MH_CreateHook(&ImmAssociateContext,    &_ImmAssociateContext,    (LPVOID*)&__ImmAssociateContext);
                MH_CreateHook(&ImmGetOpenStatus,       &_ImmGetOpenStatus,       (LPVOID*)&__ImmGetOpenStatus);
                
                MH_EnableHook(&ImmSetConversionStatus);
                MH_EnableHook(&ImmAssociateContext);
                MH_EnableHook(&ImmGetOpenStatus);
                
                /*
                pidOfCurrentProcess = GetCurrentProcessId();
                while (g_hFFXIV = FindWindowEx(NULL, g_hFFXIV, TEXT("FFXIVGAME"), NULL))
                {
                    DebugLog(TEXT("FindWindowEx : %X"), g_hFFXIV);
                    if (GetWindowThreadProcessId(g_hFFXIV, &pidOfWindow) && pidOfWindow == pidOfCurrentProcess)
                    {
                        findFFXIVWindow = TRUE;
                        break;;
                    }
                }

                if (findFFXIVWindow)
                {
                    if (GetWindowText(g_hFFXIV, oldTitle, MAX_PATH) > 0)
                        lstrcpy(g_oldTitle, oldTitle);

                    DebugLog(TEXT("oldTitle : %s"), oldTitle);

                    newTitle[0] = TEXT('_');
                    lstrcpy(newTitle + 1, g_oldTitle);

                    SetWindowText(g_hFFXIV, newTitle);
                }
                else
                    g_hFFXIV = NULL;
                */
            }
            
            break;

        case DLL_PROCESS_DETACH:
            DebugLog(TEXT("DLL_PROCESS_DETACH"));

            if (g_hooked)
            {
                MH_DisableHook(&ImmSetConversionStatus);
                MH_DisableHook(&ImmAssociateContext);
                MH_DisableHook(&ImmGetOpenStatus);

                MH_RemoveHook(&ImmSetConversionStatus);
                MH_RemoveHook(&ImmAssociateContext);
                MH_RemoveHook(&ImmGetOpenStatus);

                MH_Uninitialize();

                /*
                if (g_hFFXIV != NULL)
                    SetWindowText(g_hFFXIV, g_oldTitle);
                */
            }
            break;
    }

    return TRUE;
}
