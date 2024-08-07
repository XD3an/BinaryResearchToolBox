// #include <debugapi.h>
#include <Windows.h>
#include <winternl.h>

BOOL Check()
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
            return TRUE;
        else
            return FALSE;
    }
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