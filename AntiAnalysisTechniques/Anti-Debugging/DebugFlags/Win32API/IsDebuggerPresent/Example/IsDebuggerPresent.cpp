// #include <debugapi.h>
#include <windows.h>

int main()
{
    if (IsDebuggerPresent())
    {
        MessageBoxA(NULL, "Debugger Detected", "info", MB_OK);
        ExitProcess(-1);
    }
    else
        MessageBoxA(NULL, "Debugger Not Detected", "info", MB_OK);
    return 0;
}