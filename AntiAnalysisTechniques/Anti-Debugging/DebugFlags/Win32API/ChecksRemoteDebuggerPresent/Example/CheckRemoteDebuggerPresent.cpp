// #include <debugapi.h>   
#include <Windows.h>

int main()
{
    BOOL bDebuggerPresent;
    if (TRUE == CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) &&
        TRUE == bDebuggerPresent)
    {
        MessageBoxA(NULL, "Debugger Detected", "info", MB_OK);
        ExitProcess(-1);
    }
    else
        MessageBoxA(NULL, "Debugger Not Detected", "info", MB_OK);

    return 0;
}