#include <windows.h>

BOOL APIENTRY DllMain(
    HANDLE hModule,            // Handle to DLL module
    DWORD ul_reason_for_call,  // Reason for calling function
    LPVOID lpReserved)         // Reserved
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:   // A process is loading the DLL.
        //MessageBoxA(NULL, "DLL PROCESS ATTACH", "info", MB_OK | MB_ICONINFORMATION);
        MessageBoxA(NULL, "Say Goodbye to your process~", "You got hacked!", MB_OK | MB_ICONINFORMATION);
        break;
    /*
    case DLL_THREAD_ATTACH:    // A process is creating a new thread.
        MessageBoxA(NULL, "DLL THREAD ATTACH", "info", MB_OK | MB_ICONINFORMATION);
        break;
    case DLL_THREAD_DETACH:    // A thread exits normally.
        MessageBoxA(NULL, "DLL PROCESS DETACH", "info", MB_OK | MB_ICONINFORMATION);
        break;
    case DLL_PROCESS_DETACH:   // A process unloads the DLL.
        MessageBoxA(NULL, "DLL THREAD DETACH", "info", MB_OK | MB_ICONINFORMATION);
        break;
    */
    }
    return TRUE;
}