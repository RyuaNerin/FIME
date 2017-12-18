#include "stdafx.h"

#ifdef _DEBUG
#define _CRT_SECURE_NO_WARNINGS

#include <memory>
#include <iostream>
#include <string>

#include <windows.h>

#include "debugLog.h"

void DebugLog(const wchar_t* fmt, ...)
{
    size_t result;
    size_t length = std::wcslen(fmt);

    std::unique_ptr<wchar_t[]> pstr;
    va_list va;
    do
    {
        pstr.reset(new wchar_t[length]());
        wcscat_s(pstr.get(), length, fmt);

        va_start(va, fmt);
        result = _vsnwprintf_s(pstr.get(), length, length, fmt, va);
        va_end(va);

        length += 32;
    } while (result == -1);

    std::wcout << std::wstring(pstr.get()) << std::endl;
}

void DebugLog(const char* fmt, ...)
{
    size_t result;
    size_t length = std::strlen(fmt);

    std::unique_ptr<char[]> pstr;
    va_list va;
    do
    {
        pstr.reset(new char[length]());
        strcat_s(pstr.get(), length, fmt);

        va_start(va, fmt);
        result = _vsnprintf_s(pstr.get(), length, length, fmt, va);
        va_end(va);

        length += 32;
    } while (result == -1);

    std::cout << std::string(pstr.get()) << std::endl;
}
#endif
