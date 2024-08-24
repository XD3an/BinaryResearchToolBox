#include <windows.h>
#include <stdio.h>

#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__);
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__);
#define fail(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__);
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__);

BOOLEAN DLLInjection(DWORD PID, char *dllpath, size_t sizeOfdllpath)
{
	HANDLE hProcess, hThread = NULL;
	DWORD TID;
	LPVOID AllocBuffer;

	// 1. open process and get a handle of targeted process
	info("1. open process and got a handle of targeted process.");
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess == NULL)
	{
		fail("Failed tp open process and got a handle of targeted process!");
		return FALSE;
	}
	okay("Successfully open process and got a handle (%d)\n", PID);

	// 2. allocate the buffer within the virtual address space of the targeted process
	info("2. allocate the buffer within the virtual address space of the targeted process.");
	AllocBuffer = VirtualAllocEx(hProcess, NULL, sizeOfdllpath, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	if (AllocBuffer == NULL)
	{
		fail("Failed to Allocate Buffer!");
		return FALSE;
	}
	okay("Successfully allocate the buffer into virtual address space od the targeted process.");
	info("AllocBuffer @ %p\n", AllocBuffer);

	// 3. write the DLL PATH into the virtual address space
	info("3. write the DLL PATH into the virtual address space.");
	if (WriteProcessMemory(hProcess, AllocBuffer, dllpath, sizeOfdllpath, NULL) == 0)
	{
		fail("Failed to write dll into virtual address space!");
		return FALSE;
	}
	okay("Successfully write the DLL PATH into the virtual address space (%d).\n", PID);

	// 4. get the virtual address of "LoadLibraryA" of kernel32 module.
	info("4. get the virtual address of \"LoadLibraryA\" of kernel32 module.");
	HMODULE hkernel32 = GetModuleHandleA("kernel32.dll");
	if (hkernel32 == NULL)
	{
		fail("Failed to got the handle of Kernel32 module!");
		return FALSE;
	}
	FARPROC pLoadLibraryA = GetProcAddress(hkernel32, "LoadLibraryA");
	if (pLoadLibraryA == NULL)
	{
		fail("Failed to got the virtual address of \"LoadLibraryA\"!");
		return FALSE;
	}
	okay("Successfully get the virtual address of \"LoadLibraryA\"");
	info("\"LoadLibraryA\" @ %p\n", pLoadLibraryA);

	// 5. create a thread to load the dll adn run it
	info("5. create a thread to load the dll adn run it.");
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, AllocBuffer, 0, &TID);
	if (hThread == NULL)
	{
		fail("Failed to create the thread!");
		return FALSE;
	}
	info("Thread ID: %d\n", TID);
	WaitForSingleObject(hThread, INFINITE);
	if (hThread) {
		info("closing handle to thread");
		CloseHandle(hThread);
	}

	if (hProcess) {
		info("closing handle to process");
		CloseHandle(hProcess);
	}

	okay("Done!");
	return TRUE;
}


int main(int argc, char** argv)
{
	/* ------------------------------------- variable declartion ------------------------------------- */
	HANDLE hProcess;
	DWORD PID;
	char* dllpath;
	size_t sizeOfdllpath;

	/* --------------------------------------- Prepare Phase ----------------------------------------- */
	if (argc < 3)
	{
		warn("Usage: %s <PID>, <DllPath>", argv[0]);
		return EXIT_FAILURE;
	}

	// PID
	PID = atoi(argv[1]);
	info("Targeted PID: %d", PID);

	// DLL PATH
	dllpath = argv[2];
	sizeOfdllpath = strlen(dllpath) + 1;
	info("DLL PATH: %s", dllpath);
	info("DLL PATH size: %lld\n", sizeOfdllpath);

	/* --------------------------------------- Injection Phase --------------------------------------- */
	BOOLEAN result = DLLInjection(PID, dllpath, sizeOfdllpath);
	if (result == FALSE)
		return EXIT_FAILURE;
	else
		return EXIT_SUCCESS;
}