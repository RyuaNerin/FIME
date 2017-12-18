#pragma once

#ifdef _DEBUG
void DebugLog(const wchar_t *fmt, ...);
void DebugLog(const char *fmt, ...);
#else
#define DebugLog
#define DebugLog
#endif
