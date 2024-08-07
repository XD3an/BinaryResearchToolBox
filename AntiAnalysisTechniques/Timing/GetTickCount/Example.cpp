#include <Windows.h>

bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = GetTickCount();
    // ... some work
    for(int i = 0; i < 1000000; i++);
    return (GetTickCount() - dwStart) > dwNativeElapsed;
}

int main()
{
    if (IsDebugged(1000))
    {
        MessageBoxA(NULL, "Debugger Detected", "info", MB_OK);
        ExitProcess(-1);
    }
    else
        MessageBoxA(NULL, "Debugger Not Detected", "info", MB_OK);
    return 0;  
}
