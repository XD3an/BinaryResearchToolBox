#include "hookdll.h"

//DWORD g_originalMessageBoxW = NULL;
char g_oldcode[5] = { 0 };
char g_newcode[5] = { 0xE9 };

int WINAPI Hook_MessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    int result = MessageBoxA(0, "You've got hook!", "info", MB_OK);
    return result;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{

    DWORD originalAddr = NULL;
    const char* TargetModule = "user32.dll";
    const char* TargetFunc = "MessageBoxW";

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitHook(TargetModule, TargetFunc, originalAddr);
        InstallHook(TargetModule, TargetFunc, originalAddr);
        break;
    case DLL_PROCESS_DETACH:
        UninstallHook(TargetModule, TargetFunc, originalAddr);
        break;
    }
    return TRUE;
}

BOOL InitHook(const char* DLLName, const char* DLLfuncName, DWORD &originalAddr)
{
    HMODULE hModule = GetModuleHandleA(DLLName);
    if (!hModule)
        return FALSE;

    originalAddr = reinterpret_cast<DWORD>(GetProcAddress(hModule, DLLfuncName));

    // Hook: MessageBoxW 
    if (originalAddr)
    {
        memcpy(g_oldcode, (char*)originalAddr, sizeof(g_oldcode));
        // calculate offset
        DWORD offset = reinterpret_cast<DWORD>(Hook_MessageBoxW) - (originalAddr + 5);
        memcpy(&g_newcode[1], &offset, 4);
        return TRUE;
    }
}

BOOL InstallHook(const char* DLLName, const char* DLLfuncName, DWORD &originalAddr)
{
    DWORD oldProtect = NULL;
    VirtualProtect((DWORD*)originalAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((DWORD*)originalAddr, g_newcode, 5);
    VirtualProtect((DWORD*)originalAddr, 5, oldProtect, &oldProtect);
    return TRUE;
}

BOOL UninstallHook(const char* DLLName, const char* DLLfuncName, DWORD &originalAddr)
{
    DWORD oldProtect = NULL;
    VirtualProtect((DWORD*)originalAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((DWORD*)originalAddr, g_oldcode, 5);
    VirtualProtect((DWORD*)originalAddr, 5, oldProtect, &oldProtect);
    return TRUE;
}

