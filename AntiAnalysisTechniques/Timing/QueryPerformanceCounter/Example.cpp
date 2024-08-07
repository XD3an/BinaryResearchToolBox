#include <Windows.h>

bool IsDebugged(DWORD64 qwNativeElapsed)
{
    LARGE_INTEGER liStart, liEnd;
    QueryPerformanceCounter(&liStart);
    // ... some work
    for(int i = 0; i < 100000; i++);
    QueryPerformanceCounter(&liEnd);
    return (liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsed;
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