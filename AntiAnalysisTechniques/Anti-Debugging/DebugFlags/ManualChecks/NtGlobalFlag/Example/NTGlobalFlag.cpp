//#include <iostream>
// #include <debugapi.h>
#include <Windows.h>
#include <winternl.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS) // 0x70

int main()
{
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
#endif
    //printf("%x=?%x", dwNtGlobalFlag, NT_GLOBAL_FLAG_DEBUGGED);
    if (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
    {
        MessageBoxA(NULL, "Debugger Detected", "info", MB_OK);
        ExitProcess(-1);
    }
    else
        MessageBoxA(NULL, "Debugger Not Detected", "info", MB_OK);

    return 0;
}