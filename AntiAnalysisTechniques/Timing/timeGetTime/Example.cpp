#include <Windows.h>
#include <timeapi.h>

bool IsDebugged(DWORD dwNativeElapsed)
{
    DWORD dwStart = timeGetTime();
    // ... some work
    for(int i = 0; i < 1000000; i++);
    return (timeGetTime() - dwStart) > dwNativeElapsed;
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