#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN DWORD ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength);

int main()
{

    HMODULE hNtdll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtdll)
    {
        auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugFlag, dwReturned;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                0x1F,
                &dwProcessDebugFlag,
                sizeof(DWORD),
                &dwReturned);
            if (status == 0 && dwProcessDebugFlag == 0)
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