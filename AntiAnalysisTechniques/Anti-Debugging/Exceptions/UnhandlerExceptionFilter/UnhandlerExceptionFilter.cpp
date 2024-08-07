#include <Windows.h>


LONG MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)
{
    PCONTEXT ctx = pExceptionInfo->ContextRecord;
    ctx->Eip += 3; // Skip \xCC\xEB\x??
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool Check()
{
    bool bDebugged = true;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)MyUnhandledExceptionFilter);
    __asm
    {
        int 3                      // CC
        jmp near being_debugged    // EB ??
    }
    bDebugged = false;

being_debugged:
    return bDebugged;
}

int main()
{
    if (Check())
    {
        MessageBoxA(NULL, "Debugger Detected", "info", MB_OK);
        ExitProcess(-1);
    }
    else
        MessageBoxA(NULL, "Debugger Not Detected", "info", MB_OK);
    return 0;
}