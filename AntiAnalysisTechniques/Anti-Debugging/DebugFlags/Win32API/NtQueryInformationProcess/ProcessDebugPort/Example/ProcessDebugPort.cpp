#include <Windows.h>
#include <winternl.h>
#include <iostream>

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

int main()
{
    HMODULE hNtdll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtdll)
    {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugPort, dwReturned;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &dwProcessDebugPort,
                sizeof(DWORD),
                &dwReturned);
            if (status == 0 && dwProcessDebugPort != 0)
            {
                MessageBoxA(NULL, "Debugger Detected", "info", MB_OK);
                ExitProcess(-1);
            }
            else
                MessageBoxA(NULL, "Debugger Not Detected", "info", MB_OK);
        }
    }
    return 0;
}