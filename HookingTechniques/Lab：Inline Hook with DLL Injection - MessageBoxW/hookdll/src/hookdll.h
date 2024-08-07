#pragma once

#include <Windows.h>

BOOL InitHook(const char* DLLName, const char* DLLfuncName, DWORD &originalAddr);
BOOL InstallHook(const char* DLLName, const char* DLLfuncName, DWORD &originalAddr);
BOOL UninstallHook(const char* DLLName, const char* DLLfuncName, DWORD &originalAddr);

